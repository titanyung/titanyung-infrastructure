"""Nonblocking dashboard reads: fresh rows, independently dated cached totals."""
import copy
from contextlib import closing
from pathlib import Path
import sqlite3
import threading
import time


COLUMNS = ('origin,id,user,source,destination,ingress server,route_type,relay,'
           'started,ended,upload,download,status,traffic_known')
FIELDS = ('from_ts','to_ts','page','view','user','server','type','relay','q',
          'min_bytes','min_seconds','status')


class LiveAPI:
    def __init__(self, base, manifest, seed):
        self.base, self.manifest = base, manifest
        self.lock = threading.RLock()
        self.busy = set()
        self.attempted = {}
        self.template = copy.deepcopy(seed)
        self.whole = copy.deepcopy(seed['whole'])
        self.whole_at = time.monotonic()
        self.aggregate_at = 0
        self.usage_at = 0
        self.meta = {}
        self.row_cache = {}
        # This count is from the protected API, never relabelled as current.
        self.seed_meta = {'total':seed.get('records_total'),
            'users':seed.get('record_users',[]),
            'at':int(manifest.get('snapshot_saved_at',manifest['cutoff']-1)),
            'monotonic':0,'main_total':None}

    def _launch(self, key, function):
        with self.lock:
            now=time.monotonic()
            if key in self.busy or now-self.attempted.get(key,-1000)<(10 if key=='whole' else 15 if key=='usage' else 60):
                return
            self.busy.add(key)
            self.attempted[key]=now
        def work():
            try:
                function()
            except Exception as error:
                print('topology_live_refresh '+str(key[0] if isinstance(key,tuple) else key)+' '+type(error).__name__,flush=True)
            finally:
                with self.lock:self.busy.discard(key)
        threading.Thread(target=work,daemon=True).start()

    def _db(self, seconds):
        db=sqlite3.connect(Path(self.base.WHOLE_DB_PATH).resolve().as_uri()+'?mode=ro',uri=True,timeout=1)
        db.row_factory=sqlite3.Row
        deadline=time.monotonic()+seconds
        db.set_progress_handler(lambda:time.monotonic()>deadline,10000)
        return db

    def _plan(self, query):
        now=int(time.time());cutoff=max(int(self.base.TRAFFIC_START_TS),now-30*86400)
        def field(name):return str(query.get(name,[''])[0])[:128]
        def number(name,default,maximum):
            value=field(name)
            if not value:return default
            result=int(value)
            if result<0 or result>maximum:raise ValueError('invalid '+name)
            return result
        start=max(cutoff,number('from_ts',cutoff,now+86400))
        end=min(now+86400,number('to_ts',now+86400,now+86400))
        page=number('page',0,100000)
        view=field('view') or 'first_hop'
        if view not in ('first_hop','exit_observations'):raise ValueError('invalid view')
        ingress=field('server');route=field('type');relay=field('relay');status=field('status')
        if ingress and ingress not in tuple(self.base.FIRST_HOP_INGRESSES)+('进站待核实',):raise ValueError('invalid ingress')
        if route and route not in ('直连','中转','待核实'):raise ValueError('invalid route')
        if status and status not in ('active','closed'):raise ValueError('invalid status')
        if relay and relay not in ('直连','Kookeey','ByteVirt-HK ISP','DMIT','NoSLA','出站待核实','BWH','GoMami','Lazycat-SG','Lazycat-HKT','NexIP SG','ip2up.com','proxyhive.io','zorocloud','ZORO-SG','ByteVirt-TW','Uzuma-SG-Singtel1','Uzuma-SG-StarHub','Uzuma-HKT','paoluz SG','paoluz HK','paoluz ALL'):raise ValueError('invalid relay')
        allowed=self.base.EGRESS_ONLY_INGRESSES if view=='exit_observations' else self.base.FIRST_HOP_INGRESSES
        where=['started>=?','started<=?','traffic_known=1',"route_type IN ('直连','中转','待核实')",
               'ingress IN ('+','.join('?' for _ in allowed)+')']
        args=[start,end,*allowed]
        for column,value in (('user',field('user')),('ingress',ingress),('route_type',route),('relay',relay),('status',status)):
            if value:where.append(column+'=?');args.append(value)
        if field('q'):where.append('destination LIKE ?');args.append('%'+field('q')+'%')
        minimum=number('min_bytes',0,10**15)
        if minimum:where.append('upload+download>=?');args.append(minimum)
        seconds=number('min_seconds',0,10**9)
        if seconds:
            where.append("(CASE WHEN ended>started THEN ended-started WHEN status='active' THEN ?-started ELSE NULL END)>=?")
            args.extend((now,seconds))
        key=tuple((name,field(name)) for name in FIELDS if name!='page' and field(name))
        index='idx_unified_user' if field('user') else 'idx_unified_ingress' if ingress or view=='exit_observations' else 'idx_unified_started'
        if relay in ('zorocloud','ZORO-SG','ByteVirt-TW','Uzuma-SG-Singtel1','Uzuma-SG-StarHub','Uzuma-HKT','paoluz SG','paoluz HK','paoluz ALL') and view=='first_hop':
            where.extend(("ingress IN ('DMIT','Lazycat-SG-Front')","route_type='中转'"))
            index='idx_unified_hk_usage'
        elif relay in ('Lazycat-SG','Lazycat-HKT') and view=='first_hop':
            where.extend(("origin IN ('dmit','bwh','lazycat')","route_type='中转'"))
            index='idx_unified_hk_usage'
        elif relay=='ByteVirt-HK ISP' and self.manifest.get('server_policy') in ('dmit-domain-routing-20261106','dmit-domain-routing-20261109-v2') and view=='first_hop':
            where.extend(("origin IN ('dmit','hk','bwh')","route_type='中转'"))
            index='idx_unified_hk_usage'
        is_default=not key
        long_where=list(where);long_where[0]='started<?'
        long_where[1]="(CASE WHEN status='closed' THEN COALESCE(ended,changed) ELSE changed END) BETWEEN ? AND ?"
        long_where.extend(("origin IN ('dmit','bwh')","id>='static:'","id<'static;'"))
        return {'where':' AND '.join(where),'args':args,'page':page,'view':view,
                'route':route,'index':index,'key':key,'default':is_default,
                'start':start,'end':end,'allowed':allowed,'long_index':index,
                'long_where':' AND '.join(long_where),'long_args':[start,start,end,*args[2:]]}

    def _rows(self, plan):
        with closing(self._db(2)) as db:
            rows=[dict(row) for row in db.execute('SELECT '+COLUMNS+' FROM unified_records INDEXED BY '+plan['index']+
                ' WHERE '+plan['where']+' ORDER BY started DESC,origin,id LIMIT 100 OFFSET ?',plan['args']+[plan['page']*100])]
            if len(rows)<100:
                with self.lock:metadata=self.meta.get(plan['key']) or {}
                main_total=metadata.get('main_total')
                if plan['page']==0 or main_total is not None:
                    offset=max(0,plan['page']*100-int(main_total or 0))
                    rows.extend(dict(row) for row in db.execute('SELECT '+COLUMNS+' FROM unified_records INDEXED BY '+plan['long_index']+' WHERE '+plan['long_where']+
                        ' ORDER BY started DESC,origin,id LIMIT ? OFFSET ?',plan['long_args']+[100-len(rows),offset]))
                elif not rows:
                    raise sqlite3.OperationalError('page metadata pending')
        if plan['view']=='exit_observations':
            for row in rows:
                row['stored_ingress']=row['server'];row['server']=None;row['first_hop_confirmed']=False
                peer=str(row.get('source') or '').rsplit(':',1)[0]
                row['observed_hop']={'179.255.136.79':'DMIT','45.78.70.23':'BWH','103.26.8.100':'GoMami','216.23.117.226':'NoSLA'}.get(peer)
                row['observed_exit']=row.get('relay') if row.get('relay')!='直连' else 'ByteVirt-HK ISP'
        return rows

    def _count(self, plan):
        # Combining verified and uncertain classes defeats the old partial
        # covering index. Group each separately; count and users share a pass.
        totals={};predicate="route_type IN ('直连','中转','待核实')"
        with closing(self._db(6)) as db:
            for replacement,index in (("route_type IN ('直连','中转')",'idx_unified_dashboard_cover'),("route_type='待核实'",'idx_unified_unverified_count')):
                if plan['route']=='待核实' and 'IN' in replacement:continue
                if plan['route'] in ('直连','中转') and 'IN' not in replacement:continue
                clause=plan['where'].replace(predicate,replacement,1)
                # The first-hop covering index remains valid for diagnostic
                # slices, but ingress index is more selective there.
                if plan['view']=='exit_observations':index='idx_unified_ingress'
                if plan['index']=='idx_unified_hk_usage':index='idx_unified_hk_usage'
                for row in db.execute('SELECT user,COUNT(*) n FROM unified_records INDEXED BY '+index+' WHERE '+clause+' GROUP BY user',plan['args']):
                    totals[row['user']]=totals.get(row['user'],0)+row['n']
            main_total=sum(totals.values())
            for row in db.execute('SELECT user,COUNT(*) n FROM unified_records INDEXED BY '+plan['long_index']+' WHERE '+plan['long_where']+' GROUP BY user',plan['long_args']):
                totals[row['user']]=totals.get(row['user'],0)+row['n']
        value={'total':sum(totals.values()),'users':sorted(totals),'at':int(time.time()),
               'monotonic':time.monotonic(),'main_total':main_total}
        with self.lock:self.meta[plan['key']]=value

    def _refresh_whole(self):
        value=self.base.whole_payload()
        with self.lock:self.whole=value;self.whole_at=time.monotonic()

    def _refresh_aggregate(self):
        value=self.base.aggregate_payload('','','','')
        with self.lock:
            for key in ('summary','users','events','sources','retention_days'):
                if key in value:self.template[key]=value[key]
            self.template.pop('bootstrap_saved_at',None)
            self.aggregate_at=time.monotonic()

    def _refresh_usage(self):
        # This is independent from access/whole aggregates: a slow count query
        # cannot stop user coverage from completing or block HTTP responses.
        try:
            began=int(time.time());rows=self.base.server_user_usage()
            with self.lock:
                self.template.update(server_user_usage=rows,server_user_usage_state='ready',
                    server_user_usage_asof=getattr(self.base,'server_user_usage_snapshot_at',began),
                    server_user_usage_pending_hosts=[])
                self.template.pop('server_user_usage_error_type',None)
                self.usage_at=time.monotonic()
        except Exception as error:
            with self.lock:
                self.template.update(server_user_usage_state='pending',
                    server_user_usage_pending_hosts=list(self.manifest.get('active_hosts',[])),
                    server_user_usage_error_type=type(error).__name__)
            print('topology_user_usage_refresh '+type(error).__name__,flush=True)

    def payload(self, query):
        plan=self._plan(query);now=time.monotonic()
        with self.lock:
            metadata=copy.deepcopy(self.meta.get(plan['key']) or (self.seed_meta if plan['default'] else {'total':None,'users':self.seed_meta['users'],'at':None,'monotonic':0}))
            payload=copy.deepcopy(self.template);payload['whole']=copy.deepcopy(self.whole)
            whole_due=now-self.whole_at>=15;aggregate_due=now-self.aggregate_at>=60
            usage_due=self.template.get('server_user_usage_state')!='ready' or now-self.usage_at>=60
        # Latest rows are always a fresh indexed read; an old seed is never
        # used as a substitute for newly observed zorocloud connections.
        rows=self._rows(plan)
        payload.update(records=rows,records_total=metadata['total'],records_page=plan['page'],
            records_page_size=100,record_users=sorted(set(metadata['users'])|{row['user'] for row in rows}),
            records_count_asof=metadata['at'],records_count_pending=not metadata['monotonic'] or now-metadata['monotonic']>=60,
            records_rows_asof=int(time.time()),records_has_more=len(rows)==100)
        if now-metadata['monotonic']>=60:self._launch('metadata',lambda:self._count(plan))
        if whole_due:self._launch('whole',self._refresh_whole)
        if usage_due:self._launch('usage',self._refresh_usage)
        if aggregate_due:self._launch('aggregate',self._refresh_aggregate)
        return payload

#!/usr/bin/env python3

import io

from flask import (
    Flask,
    Response,
    jsonify,
    request,
)

import qrcode
import qrcode.image.svg


APP = Flask(__name__)


@APP.get("/health")
def health():

    return jsonify({
        "ok": True
    })



@APP.get("/qr")
def qr_get():

    text = str(
        request.args.get(
            "text",
            ""
        )
    ).strip()

    if not text:

        return jsonify({
            "error":
                "missing text"
        }), 400

    if len(text) > 4096:

        return jsonify({
            "error":
                "text too long"
        }), 400

    image = qrcode.make(
        text,
        image_factory=
            qrcode.image.svg.SvgPathImage,
        box_size=10,
        border=4,
    )

    buf = io.BytesIO()

    image.save(
        buf
    )

    return Response(
        buf.getvalue(),
        content_type=
            "image/svg+xml",
        headers={
            "Cache-Control":
                "no-store",
        }
    )


@APP.post("/qr")
def qr():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    text = str(
        data.get(
            "text",
            ""
        )
    ).strip()


    if not text:

        return jsonify({
            "error":
                "missing text"
        }), 400


    # 防止被当成无限二维码生成器
    if len(text) > 4096:

        return jsonify({
            "error":
                "text too long"
        }), 400


    image = qrcode.make(
        text,
        image_factory=
            qrcode.image.svg.SvgPathImage,
        box_size=10,
        border=4,
    )


    buf = io.BytesIO()

    image.save(
        buf
    )


    return Response(
        buf.getvalue(),
        content_type=
            "image/svg+xml",
        headers={
            "Cache-Control":
                "no-store",
        }
    )


if __name__ == "__main__":

    APP.run(
        host="127.0.0.1",
        port=18084,
        debug=False,
    )

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
import pyotp
import time
import sqlite3
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI(title="2FA管理系统", version="1.0.0")

DATABASE = "twofa.db"

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS twofa_configs (
            name TEXT PRIMARY KEY,
            secret TEXT NOT NULL,
            qr_uri TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class TwoFARequest(BaseModel):
    name: str
    secret: Optional[str] = None

class TwoFAResponse(BaseModel):
    name: str
    secret: str
    qr_uri: str

class TOTPResponse(BaseModel):
    name: str
    code: str
    expires_at: int

@app.get("/")
def root():
    return FileResponse("static/index.html")

@app.post("/2fa/add", response_model=TwoFAResponse)
def add_twofa(request: TwoFARequest):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT name FROM twofa_configs WHERE name = ?', (request.name,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="该名称已存在")

    secret = request.secret or pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    qr_uri = totp.provisioning_uri(name=request.name, issuer_name="2FA管理系统")

    c.execute('INSERT INTO twofa_configs (name, secret, qr_uri) VALUES (?, ?, ?)',
              (request.name, secret, qr_uri))
    conn.commit()
    conn.close()

    return TwoFAResponse(
        name=request.name,
        secret=secret,
        qr_uri=qr_uri
    )

@app.get("/2fa/list", response_model=List[TwoFAResponse])
def list_twofa():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT name, secret, qr_uri FROM twofa_configs')
    rows = c.fetchall()
    conn.close()
    
    return [
        TwoFAResponse(
            name=row[0],
            secret=row[1],
            qr_uri=row[2]
        )
        for row in rows
    ]

@app.get("/2fa/get/{name}", response_model=TwoFAResponse)
def get_twofa(name: str):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT name, secret, qr_uri FROM twofa_configs WHERE name = ?', (name,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="未找到该2FA配置")

    return TwoFAResponse(
        name=row[0],
        secret=row[1],
        qr_uri=row[2]
    )

@app.put("/2fa/update/{name}", response_model=TwoFAResponse)
def update_twofa(name: str, request: TwoFARequest):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT name FROM twofa_configs WHERE name = ?', (name,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="未找到该2FA配置")

    secret = request.secret or pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    qr_uri = totp.provisioning_uri(name=request.name, issuer_name="2FA管理系统")

    c.execute('UPDATE twofa_configs SET name = ?, secret = ?, qr_uri = ? WHERE name = ?',
              (request.name, secret, qr_uri, name))
    conn.commit()
    conn.close()

    return TwoFAResponse(
        name=request.name,
        secret=secret,
        qr_uri=qr_uri
    )

@app.delete("/2fa/delete/{name}")
def delete_twofa(name: str):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('DELETE FROM twofa_configs WHERE name = ?', (name,))
    
    if c.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="未找到该2FA配置")
    
    conn.commit()
    conn.close()
    return {"message": "删除成功"}

@app.get("/2fa/generate/{name}", response_model=TOTPResponse)
def generate_code(name: str):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT secret FROM twofa_configs WHERE name = ?', (name,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="未找到该2FA配置")

    secret = row[0]
    totp = pyotp.TOTP(secret)
    code = totp.now()
    expires_at = int(time.time()) + (30 - int(time.time()) % 30)

    return TOTPResponse(
        name=name,
        code=code,
        expires_at=expires_at
    )

@app.get("/2fa/verify/{name}")
def verify_code(name: str, code: str):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT secret FROM twofa_configs WHERE name = ?', (name,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="未找到该2FA配置")

    secret = row[0]
    totp = pyotp.TOTP(secret)
    valid = totp.verify(code, valid_window=1)

    if valid:
        return {"message": "验证通过", "valid": True}
    else:
        return {"message": "验证失败", "valid": False}

app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    import uvicorn
    port=8123   # 端口号
    print("🚀 2FA管理系统启动成功")
    print(f"📡 服务地址: http://127.0.0.1:{port}")
    print(f"🌐 外网访问: http://0.0.0.0:{port}")
    print("按 Ctrl+C 停止服务")
    uvicorn.run(app, host="0.0.0.0", port=port)

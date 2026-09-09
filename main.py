from fastapi import FastAPI, HTTPException, Query, Depends, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import select, or_
from database import get_db
from models import Log, LogCreate, Base
from database import engine

Base.metadata.create_all(bind=engine)



app = FastAPI()

logs = [
    {
        "id": 1,
        "ip": "192.168.1.5",
        "username": "john",
        "action": "failed_login",
    },
    {
        "id": 2,
        "ip": "10.0.0.8",
        "username": "admin",
        "action": "login",
    },
]

def parse_log_line(line: str):
    parts = line.split()
    if len(parts) != 5:
        return None
    return {
        "ip":parts[2],
        "username":parts[3],
        "action":parts[4]
    }

@app.get("/")
def root():
    return {"message": "SIEM API running"}


@app.get("/logs")
def get_logs(db: Session = Depends(get_db), action: str | None = None,
                username : str | None = None,
                ip: str | None = None,
                search: str | None = None,
                limit: int = Query(default=100, ge=1, le=1000)):
        stmt = select(Log)
        if action is not None: 
            stmt = stmt.where(Log.action==action)
        if username is not None: 
            stmt = stmt.where(Log.username==username)
        if ip is not None: 
            stmt = stmt.where(Log.ip==ip)
        if search is not None:
            pattern = f"%{search}%"
            condition = or_(
                Log.username.ilike(pattern),
                Log.action.ilike(pattern),
                Log.ip.ilike(pattern)
            )
            stmt = stmt.where(condition)
        stmt = stmt.limit(limit)
        results = db.scalars(stmt).all()
        return results

@app.get("/logs/{log_id}")
def get_log(log_id:int, db: Session = Depends(get_db)):
    log = db.get(Log, log_id)
    if log is None:
        raise HTTPException(
                status_code=404,
                detail="Log not found"
        )
    return log


@app.post("/logs")
def create_log(log: LogCreate , db: Session = Depends(get_db)): #LogCreate class makes the incoming json body accessible
    new_log = Log(
        username=log.username,
        action=log.action,
        ip=log.ip,
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    return new_log

@app.put("/logs/{log_id}")
def update_log(log_id: int, updated_log:LogCreate, db: Session = Depends(get_db)):
    log = db.get(Log, log_id)
    if log is not None:
        log.username = updated_log.username
        log.ip = updated_log.ip
        log.action = updated_log.action
        db.commit()
        db.refresh(log)
        return {{"message": "Log updated"}}
    raise HTTPException(
        status_code=404,
        detail="Log not found"
    )

@app.delete("/logs/{log_id}")
def delete_log(log_id: int, db: Session = Depends(get_db)):
    log = db.get(Log, log_id)
    if log is not None:
        db.delete(log)
        db.commit()
        return {{"message": "Log deleted"}}
    raise HTTPException(
        status_code=404,
        detail="Log not found"
    )

@app.post("/logs/upload")
async def upload_file(file: UploadFile, db:Session = Depends(get_db)):
    content = await file.read()
    decoded = content.decode("utf-8")
    lines = decoded.splitlines()
    amount = 0
    for line in lines:
        parsed_log = parse_log_line(line)
        if parsed_log is not None:
            log = Log(
                username=parsed_log["username"],
                action=parsed_log["action"],
                ip=parsed_log["ip"]
            )            
            db.add(log)
            amount += 1
    db.commit()
    return {"filename": file.filename, "total_lines": len(lines), "valid_logs": amount}
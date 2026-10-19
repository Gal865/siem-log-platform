from fastapi import FastAPI, HTTPException, Query, Depends, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import select, or_
from database import get_db
from models import Log, LogCreate, Base, RuleCreate, Rule, Alert, AlertLog, PatchRequest
from database import engine
from zoneinfo import ZoneInfo
import ipaddress
from datetime import datetime, timezone, timedelta
import traceback 
import time
from database import SessionLocal

allowed_patch = {'.json'}

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

valid_severity = ["WARNING","INFO","ERROR","CRITICAL"]

def run_rule(rule:Rule, db:Session):
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(minutes=rule.window)
    stmt = (
        select(Log)
        .where(Log.action == rule.action)
        .where(Log.timestamp >= window_start)
        .where(Log.timestamp <= window_end)
    )
    candidate_logs = db.scalars(stmt).all()
    logs_by_user = {}

    #grouping logs by user
    for log in candidate_logs: 
        if log.username not in logs_by_user:
            logs_by_user[log.username] = []
        logs_by_user[log.username].append(log)

    for username,logs in logs_by_user.items():
        if len(logs) >= rule.threshold:
            stmt = (select(Alert)
                    .where(Alert.username == username)
                    .where(Alert.rule_id == rule.id)
                    .where(Alert.time >= window_start)
                    .order_by(Alert.time.desc()).limit(1)
                    )
            existing_alert = db.scalars(stmt).first()
            if existing_alert: #If a log will trigger an alert, but it within the window of the previously written alert, add it to the same alert
                stmt = select(AlertLog.log_id).where(AlertLog.alert_id == existing_alert.id)  
                existing_log_ids = set(db.scalars(stmt).all())
                for log in logs: 
                    if log.id not in existing_log_ids:
                        alertlog = AlertLog(
                            alert_id = existing_alert.id,
                            log_id = log.id
                        )
                        db.add(alertlog)
                        existing_log_ids.add(log.id)
                        existing_alert.event_count += 1                 
            else: #log is not in the previous alert window, therefore is a part of a new alert
                alert = Alert(
                    username = username,
                    time=window_end,
                    event_count=len(logs),
                    rule_id = rule.id
                )
                db.add(alert)
                db.flush() 
                for log in logs:
                    alertlog = AlertLog(
                        alert_id = alert.id,
                        log_id = log.id
                    )
                    db.add(alertlog)
    db.commit()


def parse_log_line(line: str):
    parts = line.split()
    if len(parts) != 6:
        return None
    try:
        ipaddress.ip_address(parts[2])
        timestamp = parts[0] + " " + parts[1]
        parsed_timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        parsed_timestamp = parsed_timestamp.replace(tzinfo=ZoneInfo("America/New_York"))
        parts[5] = parts[5].upper()
        if parts[5] in valid_severity:
            pass
        else:
            return None
        return {
                "timestamp": parsed_timestamp,
                "ip":parts[2],
                "username":parts[3],
                "action":parts[4],
                "severity":parts[5]
            }
    except ValueError:
        return None

@app.get("/")
def root():
    return {"message": "SIEM API running"}

@app.get("/alerts")
def get_alerts(status:str | None = None, limit: int = Query(default=50, ge=1, le=100),
offset: int = Query(default=0, ge=0), db:Session = Depends(get_db)):
    stmt = select(Alert)
    if status is not None:
        if status != "open" and status != "resolved":
            raise HTTPException(
                status_code=422,
                detail="Invalid Status"
            )
        stmt = stmt.where(Alert.status==status)
    stmt = stmt.offset(offset)
    stmt = stmt.limit(limit)
    stmt = stmt.order_by(Alert.id.desc())
    return db.scalars(stmt).all()

@app.patch("/alerts/{alert_id}/status")
def patch_alerts( alert_id: int, body: PatchRequest, db: Session = Depends(get_db)):
    if body.status != "open" and body.status != "resolved":
        raise HTTPException(
                status_code=422,
                detail="Invalid status"
            )
    stmt = select(Alert).where(Alert.id == alert_id)
    alert = db.scalars(stmt).first()
    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert Doesn't exist"
        )
    alert.status = body.status
    db.commit()
    db.refresh(alert)
    return alert

@app.get("/alerts/{alert_id}/logs")
def get_logs_of_alert(alert_id:int, db:Session = Depends(get_db)):
    stmt = (
        select(Alert)
        .where(Alert.id == alert_id)
    )
    alert = db.scalars(stmt).first()
    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )
    stmt = (
        select(Log)
        .join(AlertLog, AlertLog.log_id == Log.id)
        .where(AlertLog.alert_id == alert_id)
        )
    log_objs = db.scalars(stmt).all()
    return log_objs
    

@app.get("/logs")
def get_logs(db: Session = Depends(get_db), action: str | None = None,
                username : str | None = None,
                ip: str | None = None,
                search: str | None = None,
                severity: str | None = None,
                start_time: datetime | None = None,
                end_time: datetime | None = None,
                limit: int = Query(default=100, ge=1, le=1000),
                offset: int = Query(default=0, ge=0)):
        stmt = select(Log)
        if action is not None: 
            stmt = stmt.where(Log.action==action)
        if username is not None: 
            stmt = stmt.where(Log.username==username)
        if ip is not None: 
            stmt = stmt.where(Log.ip==ip)
        if start_time is not None:
            stmt = stmt.where(Log.timestamp >= start_time)
        if end_time is not None:
            stmt = stmt.where(Log.timestamp <= end_time)
        if offset is not None:
            stmt = stmt.offset(offset)
        if severity is not None:
            stmt = stmt.where(Log.severity==severity)
        if search is not None:
            pattern = f"%{search}%"
            condition = or_(
                Log.username.ilike(pattern),
                Log.action.ilike(pattern),
                Log.ip.ilike(pattern)
            )
            stmt = stmt.where(condition)
        stmt = stmt.limit(limit)
        stmt = stmt.order_by(Log.timestamp.desc())
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
        timestamp=datetime.now(timezone.utc),
        action=log.action,
        ip=log.ip,
        severity=log.severity
    )
    new_log.severity = new_log.severity.upper()
    if new_log.severity not in valid_severity:
        raise HTTPException(
            status_code=400,
            detail="Invalid Severity"
        )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    return new_log

@app.post("/rules")
def create_rule(rule: RuleCreate, db: Session = Depends(get_db)):
    new_rule = Rule(
        name=rule.name,
        description=rule.description,
        severity=rule.severity,
        action=rule.action,
        threshold=rule.threshold,
        window=rule.window
    )
    if new_rule.severity not in valid_severity:
        raise HTTPException(
            status_code=400,
            detail="Invalid Severity"
        )
    db.add(new_rule)
    db.commit()
    db.refresh(new_rule)
    return new_rule

@app.put("/logs/{log_id}")
def update_log(log_id: int, updated_log:LogCreate, db: Session = Depends(get_db)):
    log = db.get(Log, log_id)
    if log is not None:
        log.username = updated_log.username
        log.ip = updated_log.ip
        log.action = updated_log.action
        log.severity = updated_log.severity
        db.commit()
        db.refresh(log)
        return {"message": "Log updated"}
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
        return {"message": "Log deleted"}
    raise HTTPException(
        status_code=404,
        detail="Log not found"
    )

@app.post("/logs/upload")
async def upload_file(file: UploadFile, db: Session = Depends(get_db)):
    content = await file.read()
    decoded = content.decode("utf-8")
    lines = decoded.splitlines()
    amount = 0
    invalid_logs = []
    try:
        for line_number, line in enumerate(lines, start=1):
            parsed_log = parse_log_line(line)
            if parsed_log is None:
                invalid_logs.append({"line_number": line_number, "line": line})
                continue

            log = Log(
                timestamp=parsed_log["timestamp"],
                username=parsed_log["username"],
                action=parsed_log["action"],
                ip=parsed_log["ip"],
                severity=parsed_log["severity"]
            )
            amount += 1
            db.add(log)
        db.commit()
    except Exception as e:
        db.rollback()
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail="Failed to upload logs"
        )

    return {
        "filename": file.filename,
        "total_lines": len(lines),
        "valid_logs": amount,
        "invalid_logs": len(invalid_logs),
        "invalid_lines": invalid_logs,
    }



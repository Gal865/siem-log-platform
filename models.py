from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, DateTime, ForeignKey
from pydantic import BaseModel
from datetime import datetime

class Base(DeclarativeBase):
    pass

class Log(Base):
    __tablename__ = "logs"
    
    id : Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    username: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    ip: Mapped[str] = mapped_column(String(45))
    severity: Mapped[str] = mapped_column(String(20))

class Rule(Base):
    __tablename__ = "rules"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column()
    description: Mapped[str] = mapped_column()
    severity: Mapped[str] = mapped_column()
    alerts: Mapped[list["Alert"]] = relationship(back_populates="rule")

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column()
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column()
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id"))
    rule: Mapped[Rule] = relationship(back_populates="alerts")

class AlertLog(Base):
    __tablename__ = "alert_logs"
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), primary_key=True)
    log_id: Mapped[int] = mapped_column(ForeignKey("logs.id"), primary_key=True)

class LogCreate(BaseModel):
    username: str
    action: str
    ip: str
    severity: str

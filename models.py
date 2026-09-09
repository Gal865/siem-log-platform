from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String
from pydantic import BaseModel

class Base(DeclarativeBase):
    pass

class Log(Base):
    __tablename__ = "logs"
    
    id : Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    ip: Mapped[str] = mapped_column(String(45))

class LogCreate(BaseModel):
    username: str
    action: str
    ip: str
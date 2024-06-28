import os
import datetime
from sqlalchemy import create_engine, Integer, String, DateTime, func, ForeignKey, Text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, mapped_column, Mapped, relationship

POSTGRES_USER=os.getenv('POSTGRES_USER', "user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "1234")
POSTGRES_DB = os.getenv("POSTGRES_DB", "netology")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "127.0.0.1")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5431")

engine = create_engine(f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@"
                       f"{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}")
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    registration_time: Mapped[datetime.datetime] = mapped_column(
        DateTime,
        # default=datetime.datetime.now,
        server_default=func.now()
    )


class Advertisement(Base):
    __tablename__ = "advertisements"

    id = mapped_column(Integer, primary_key=True)
    heading = mapped_column(String(20), nullable=False)
    description = mapped_column(Text)
    date_of_creation = mapped_column(DateTime, server_default=func.now())
    user_id = mapped_column(Integer, ForeignKey("app_users.id", ondelete="CASCADE"))
    user = relationship("User", backref="advertisements")

Base.metadata.create_all(bind=engine)



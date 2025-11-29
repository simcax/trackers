from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from trackers.db.database import Base


class TrackerModel(Base):
    __tablename__ = "trackers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)

    items = relationship("ItemModel", back_populates="tracker")
    logs = relationship("LogModel", back_populates="tracker")


class ItemModel(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    tracker_id = Column(Integer, ForeignKey("trackers.id"))
    date = Column(DateTime)

    tracker = relationship("TrackerModel", back_populates="items")


class LogModel(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    message = Column(String)
    tracker_id = Column(Integer, ForeignKey("trackers.id"))

    tracker = relationship("TrackerModel", back_populates="logs")

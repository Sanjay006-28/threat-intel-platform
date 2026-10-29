from fastapi import APIRouter, Request, Depends, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Feed, FeedRun
from app.collectors.runner import run_all_collectors

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

@router.get("/feeds")
def list_feeds(request: Request, db: Session = Depends(get_db)):
    feeds = db.query(Feed).all()
    runs = db.query(FeedRun).order_by(FeedRun.id.desc()).limit(10).all()
    return templates.TemplateResponse(request=request, name="feeds.html", context={"request": request, "feeds": feeds, "runs": runs})

@router.post("/feeds/run_all")
def trigger_all_feeds(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_all_collectors)
    # Ideally use a flash message here
    return RedirectResponse(url="/feeds", status_code=303)

"""
High School Management System API

A simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr


SECRET_KEY = "mergington-school-secret-key"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# Demo user database for authentication and role handling
users = {
    "student@mergington.edu": {
        "email": "student@mergington.edu",
        "name": "Student User",
        "password": "student123",
        "role": "student",
        "grade": "10",
    },
    "admin@mergington.edu": {
        "email": "admin@mergington.edu",
        "name": "School Admin",
        "password": "admin123",
        "role": "admin",
        "grade": None,
    },
    "teacher@mergington.edu": {
        "email": "teacher@mergington.edu",
        "name": "Teacher User",
        "password": "teacher123",
        "role": "teacher",
        "grade": None,
    },
    "clubadvisor@mergington.edu": {
        "email": "clubadvisor@mergington.edu",
        "name": "Club Advisor",
        "password": "advisor123",
        "role": "club_advisor",
        "grade": None,
    },
}


# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


def create_token(user: dict) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user["email"],
        "role": user["role"],
        "exp": expires_at,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    email = payload.get("sub")
    user = users.get(email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(required_role: str):
    def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user["role"] != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{required_role.replace('_', ' ').title()} access required",
            )
        return current_user

    return role_checker


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = users.get(payload.email.lower())
    if not user or user["password"] != payload.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token = create_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
            "grade": user.get("grade"),
        },
    }


@app.get("/me")
def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    return {
        "email": current_user["email"],
        "name": current_user["name"],
        "role": current_user["role"],
        "grade": current_user.get("grade"),
    }


@app.get("/admin")
def admin_dashboard(current_user: dict = Depends(require_role("admin"))):
    return {
        "email": current_user["email"],
        "name": current_user["name"],
        "role": current_user["role"],
        "message": "Admin dashboard access granted",
    }


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str):
    """Sign up a student for an activity"""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]

    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str):
    """Unregister a student from an activity"""
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    activity = activities[activity_name]

    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}

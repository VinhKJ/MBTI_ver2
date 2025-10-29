"""FastAPI backend for URP MBTI testing application.

This backend provides:

* User registration and login with JWT based authentication.
* Endpoints to fetch MBTI question sets (PSI‑32 and MBTI‑70).
* Endpoints to score answers and optionally persist results to a database.
* Endpoint to list a user's previous test results.

The database is SQLite for simplicity, but SQLAlchemy is used so a more
robust engine (e.g. PostgreSQL) can easily be swapped in later.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

import bcrypt
from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy import (Boolean, Column, DateTime, Integer, String, JSON,
                        create_engine, ForeignKey)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-please")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./urp.sqlite")

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -----------------------------------------------------------------------------
# SQLAlchemy models
# -----------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    results = relationship("TestResult", back_populates="user")


class TestResult(Base):
    __tablename__ = "test_results"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    test_code = Column(String, nullable=False)  # "PSI32" or "MBTI70"
    type4 = Column(String, nullable=False)  # e.g. "INTJ"
    scores = Column(JSON, nullable=False)
    margins = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="results")


# Create tables
Base.metadata.create_all(bind=engine)

# -----------------------------------------------------------------------------
# Pydantic schemas
# -----------------------------------------------------------------------------

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str]
    created_at: datetime

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


class AnswerPSI(BaseModel):
    item: int
    value: int  # 0–5 where a = 5−v, b = v


class AnswerMBTI(BaseModel):
    item: int
    choice: str  # "A" or "B"


class ResultOut(BaseModel):
    id: int
    test_code: str
    type4: str
    scores: Dict[str, int]
    margins: Dict[str, int]
    created_at: datetime

    class Config:
        orm_mode = True


# -----------------------------------------------------------------------------
# Utility functions
# -----------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = get_user_by_email(db, email)
    if user and verify_password(password, user.hashed_password):
        return user
    return None


async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, token_data.email)
    if user is None:
        raise credentials_exception
    return user


# -----------------------------------------------------------------------------
# Question data
# -----------------------------------------------------------------------------

# PSI‑32 questions: each item has a and b prompt. Scoring requires a+b=5.
PSI_ITEMS: Dict[int, Dict[str, str]] = {
    1: {"a": "Making decisions after finding out what others think.", "b": "Making decisions without consulting others."},
    2: {"a": "Being called imaginative or intuitive.", "b": "Being called factual and accurate."},
    3: {"a": "Decisions about people based on data and systematic analysis.", "b": "Decisions about people based on empathy and needs/values."},
    4: {"a": "Allowing commitments to occur if others want them.", "b": "Pushing for definite commitments."},
    5: {"a": "Quiet, thoughtful time alone.", "b": "Active, energetic time with people."},
    6: {"a": "Using known effective methods.", "b": "Thinking of new methods when confronted with tasks."},
    7: {"a": "Conclusions via unemotional logic and step-by-step analysis.", "b": "Conclusions via what I feel and believe from experiences."},
    8: {"a": "Avoid making deadlines.", "b": "Seek a schedule and stick to it."},
    9: {"a": "Talk awhile then think to myself.", "b": "Talk freely for long and think later."},
    10: {"a": "Thinking about possibilities.", "b": "Dealing with actualities."},
    11: {"a": "Being thought of as a thinking person.", "b": "Being thought of as a feeling person."},
    12: {"a": "Consider every angle a long time before/after deciding.", "b": "Get info, consider awhile, then decide fairly quickly and firmly."},
    13: {"a": "Inner thoughts/feelings others cannot see.", "b": "Activities and occurrences in which others join."},
    14: {"a": "The abstract or theoretical.", "b": "The concrete or real."},
    15: {"a": "Helping others explore their feelings.", "b": "Helping others make logical decisions."},
    16: {"a": "Change and keeping options open.", "b": "Predictability and knowing in advance."},
    17: {"a": "Communicating little of my inner thinking and feelings.", "b": "Communicating freely my inner thinking and feelings."},
    18: {"a": "Possible views of the whole.", "b": "The factual details available."},
    19: {"a": "Using data, analysis and reason to make decisions.", "b": "Using common sense and conviction to make decisions."},
    20: {"a": "Planning ahead based on projections.", "b": "Planning as necessities arise, just before actions."},
    21: {"a": "Meeting new people.", "b": "Being alone, or with one close person."},
    22: {"a": "Ideas.", "b": "Facts."},
    23: {"a": "Verifiable conclusions.", "b": "Convictions."},
    24: {"a": "Keep appointments/notes in planners as much as possible.", "b": "Use planners as little as possible."},
    25: {"a": "Discuss a new unconsidered issue at length in a group.", "b": "Puzzle it out in my mind, then share with one person."},
    26: {"a": "Carry out detailed plans with precision.", "b": "Design plans/structures without necessarily carrying them out."},
    27: {"a": "Logical people.", "b": "Feeling people."},
    28: {"a": "Be free to do things on the spur of the moment.", "b": "Know well in advance what I am expected to do."},
    29: {"a": "Being the centre of attraction.", "b": "Being reserved."},
    30: {"a": "Imagining the non-existent.", "b": "Examining details of the actual."},
    31: {"a": "Experiencing emotional situations and discussions.", "b": "Using my ability to analyse situations."},
    32: {"a": "Starting meetings at a pre-arranged time.", "b": "Starting meetings when all are comfortable/ready."},
}

# PSI scoring tags: each tag string is like "1a" or "1b"; letters correspond to trait sides.
PSI_MAP = {
    "I": ["1b", "5a", "9a", "13a", "17a", "21b", "25b", "29b"],
    "E": ["1a", "5b", "9b", "13b", "17b", "21a", "25a", "29a"],
    "N": ["2a", "6b", "10a", "14a", "18a", "22a", "26b", "30a"],
    "S": ["2b", "6a", "10b", "14b", "18b", "22b", "26a", "30b"],
    "T": ["3a", "7a", "11a", "15b", "19b", "23b", "27a", "31b"],
    "F": ["3b", "7b", "11b", "15a", "19a", "23a", "27b", "31a"],
    "P": ["4a", "8a", "12a", "16a", "20b", "24b", "28a", "32b"],
    "J": ["4b", "8b", "12b", "16b", "20a", "24a", "28b", "32a"],
}

# MBTI‑70 questions: list of dictionaries with a and b options. If you add or adjust questions,
# update the list accordingly. Only a subset is shown here for brevity; full list should contain 70.
MBTI70_ITEMS: Dict[int, Dict[str, str]] = {
    1: {"a": "At a party do you: Interact with many, including strangers", "b": "At a party do you: Interact with a few, known to you"},
    2: {"a": "Are you more: Realistic than speculative", "b": "Are you more: Speculative than realistic"},
    3: {"a": "Is it worse to: Have your 'head in the clouds'", "b": "Is it worse to: Be 'in a rut'"},
    4: {"a": "Are you more impressed by: Principles", "b": "Are you more impressed by: Emotions"},
    5: {"a": "Are more drawn toward the: Convincing", "b": "Are more drawn toward the: Touching"},
    6: {"a": "Do you prefer to work: To deadlines", "b": "Do you prefer to work: Just 'whenever'"},
    7: {"a": "Do you tend to choose: Rather carefully", "b": "Do you tend to choose: Somewhat impulsively"},
    8: {"a": "At parties do you: Stay late, with increasing energy", "b": "At parties do you: Leave early with decreased energy"},
    9: {"a": "Are you more attracted to: Sensible people", "b": "Are you more attracted to: Imaginative people"},
    10: {"a": "Are you more interested in: What is actual", "b": "Are you more interested in: What is possible"},
    11: {"a": "In judging others are you more swayed by: Laws than circumstances", "b": "In judging others are you more swayed by: Circumstances than laws"},
    12: {"a": "In approaching others is your inclination to be somewhat: Objective", "b": "In approaching others is your inclination to be somewhat: Personal"},
    13: {"a": "Are you more: Punctual", "b": "Are you more: Leisurely"},
    14: {"a": "Does it bother you more having things: Incomplete", "b": "Does it bother you more having things: Completed"},
    15: {"a": "In your social groups do you: Keep abreast of others' happenings", "b": "In your social groups do you: Get behind on the news"},
    16: {"a": "In doing ordinary things are you more likely to: Do it the usual way", "b": "In doing ordinary things are you more likely to: Do it your own way"},
    17: {"a": "Writers should: 'Say what they mean and mean what they say'", "b": "Writers should: Express things more by use of analogy"},
    18: {"a": "Which appeals to you more: Consistency of thought", "b": "Which appeals to you more: Harmonious human relationships"},
    19: {"a": "Are you more comfortable in making: Logical judgments", "b": "Are you more comfortable in making: Value judgments"},
    20: {"a": "Do you want things: Settled and decided", "b": "Do you want things: Unsettled and undecided"},
    21: {"a": "Would you say you are more: Serious and determined", "b": "Would you say you are more: Easy-going"},
    22: {"a": "In phoning do you: Rarely question that it will all be said", "b": "In phoning do you: Rehearse what you'll say"},
    23: {"a": "Facts: 'Speak for themselves'", "b": "Facts: Illustrate principles"},
    24: {"a": "Are visionaries: somewhat annoying", "b": "Are visionaries: rather fascinating"},
    25: {"a": "Are you more often: a cool-headed person", "b": "Are you more often: a warm-hearted person"},
    26: {"a": "Is it worse to be: unjust", "b": "Is it worse to be: merciless"},
    27: {"a": "Should one usually let events occur: by careful selection and choice", "b": "Should one usually let events occur: randomly and by chance"},
    28: {"a": "Do you feel better about: having purchased", "b": "Do you feel better about: having the option to buy"},
    29: {"a": "In company do you: initiate conversation", "b": "In company do you: wait to be approached"},
    30: {"a": "Common sense is: rarely questionable", "b": "Common sense is: frequently questionable"},
    31: {"a": "Children often do not: make themselves useful enough", "b": "Children often do not: exercise their fantasy enough"},
    32: {"a": "In making decisions do you feel more comfortable with: standards", "b": "In making decisions do you feel more comfortable with: feelings"},
    33: {"a": "Are you more: firm than gentle", "b": "Are you more: gentle than firm"},
    34: {"a": "Which is more admirable: the ability to organize and be methodical", "b": "Which is more admirable: the ability to adapt and make do"},
    35: {"a": "Do you put more value on: infinite", "b": "Do you put more value on: open-minded"},
    36: {"a": "Does new and non-routine interaction with others: stimulate and energize you", "b": "Does new and non-routine interaction with others: tax your reserves"},
    37: {"a": "Are you more frequently: a practical sort of person", "b": "Are you more frequently: a fanciful sort of person"},
    38: {"a": "Are you more likely to: see how others are useful", "b": "Are you more likely to: see how others see"},
    39: {"a": "Which is more satisfying: to discuss an issue thoroughly", "b": "Which is more satisfying: to arrive at agreement on an issue"},
    40: {"a": "Which rules you more: your head", "b": "Which rules you more: your heart"},
    41: {"a": "Are you more comfortable with work that is: contracted", "b": "Are you more comfortable with work that is: done on a casual basis"},
    42: {"a": "Do you tend to look for: the orderly", "b": "Do you tend to look for: whatever turns up"},
    43: {"a": "Do you prefer: many friends with brief contact", "b": "Do you prefer: a few friends with more lengthy contact"},
    44: {"a": "Do you go more by: facts", "b": "Do you go more by: principles"},
    45: {"a": "Are you more interested in: production and distribution", "b": "Are you more interested in: design and research"},
    46: {"a": "Which is more of a compliment: 'There is a very logical person.'", "b": "Which is more of a compliment: 'There is a very sentimental person.'"},
    47: {"a": "Do you value in yourself more that you are: unwavering", "b": "Do you value in yourself more that you are: devoted"},
    48: {"a": "Do you more often prefer the: final and unalterable statement", "b": "Do you more often prefer the: tentative and preliminary statement"},
    49: {"a": "Are you more comfortable: after a decision", "b": "Are you more comfortable: before a decision"},
    50: {"a": "Do you: speak easily and at length with strangers", "b": "Do you: find little to say to strangers"},
    51: {"a": "Are you more likely to trust your: experience", "b": "Are you more likely to trust your: hunch"},
    52: {"a": "Do you feel: more practical than ingenious", "b": "Do you feel: more ingenious than practical"},
    53: {"a": "Which person is more to be complimented—one of: clear reason", "b": "Which person is more to be complimented—one of: strong feeling"},
    54: {"a": "Are you inclined more to be: fair-minded", "b": "Are you inclined more to be: sympathetic"},
    55: {"a": "Is it preferable mostly to: make sure things are arranged", "b": "Is it preferable mostly to: just let things happen"},
    56: {"a": "In relationships should most things be: re-negotiable", "b": "In relationships should most things be: random and circumstantial"},
    57: {"a": "When the phone rings do you: hasten to get to it first", "b": "When the phone rings do you: hope someone else will answer"},
    58: {"a": "Do you prize more in yourself: a strong sense of reality", "b": "Do you prize more in yourself: a vivid imagination"},
    59: {"a": "Are you drawn more to: fundamentals", "b": "Are you drawn more to: overtones"},
    60: {"a": "Which seems the greater error: to be too passionate", "b": "Which seems the greater error: to be too objective"},
    61: {"a": "Do you see yourself as basically: hard-headed", "b": "Do you see yourself as basically: soft-hearted"},
    62: {"a": "Which situation appeals to you more: the structured and scheduled", "b": "Which situation appeals to you more: the unstructured and unscheduled"},
    63: {"a": "Are you a person that is more: routinized than whimsical", "b": "Are you a person that is more: whimsical than routinized"},
    64: {"a": "Are you more inclined to be: easy to approach", "b": "Are you more inclined to be: somewhat reserved"},
    65: {"a": "In writings do you prefer: the more literal", "b": "In writings do you prefer: the more figurative"},
    66: {"a": "Is it harder for you to: identify with others", "b": "Is it harder for you to: utilize others"},
    67: {"a": "Which do you wish more for yourself: clarity of reason", "b": "Which do you wish more for yourself: strength of compassion"},
    68: {"a": "Which is the greater fault: being indiscriminate", "b": "Which is the greater fault: being critical"},
    69: {"a": "Do you prefer the: planned event", "b": "Do you prefer the: unplanned event"},
    70: {"a": "Do you tend to be more: deliberate than spontaneous", "b": "Do you tend to be more: spontaneous than deliberate"},
}

# Column-to-dimension map for MBTI‑70 scoring. Columns 1–7 map to pairs of opposite traits.
# Each column groups questions at ordinal positions modulo 7.
COLUMN_TO_DIM = {
    1: ("E", "I"),
    2: ("S", "N"),
    3: ("N", "S"),
    4: ("T", "F"),
    5: ("J", "P"),
    6: ("F", "T"),
    7: ("P", "J"),
}

# -----------------------------------------------------------------------------
# Scoring functions
# -----------------------------------------------------------------------------

def score_psi32(answers: List[AnswerPSI]) -> Dict[str, Any]:
    if len(answers) != 32:
        raise HTTPException(status_code=400, detail="Require 32 answers for PSI-32")
    ans_map = {a.item: a for a in answers}
    # Validate 1..32 present and values in 0..5
    for i in range(1, 33):
        a = ans_map.get(i)
        if not a:
            raise HTTPException(status_code=400, detail=f"Missing answer for item {i}")
        v = a.value
        if v < 0 or v > 5:
            raise HTTPException(status_code=400, detail=f"Value for item {i} must be between 0 and 5")
    # Compute totals
    totals = {k: 0 for k in ["I", "E", "N", "S", "T", "F", "P", "J"]}
    for trait, tags in PSI_MAP.items():
        for tag in tags:
            num = int(tag[:-1])
            side = tag[-1]
            v = ans_map[num].value
            # For side 'a', score is 5-v; for 'b', score is v
            if side == 'a':
                totals[trait] += 5 - v
            else:
                totals[trait] += v
    # Compose four-letter type
    letters = ""
    letters += "I" if totals["I"] >= totals["E"] else "E"
    letters += "N" if totals["N"] >= totals["S"] else "S"
    letters += "T" if totals["T"] >= totals["F"] else "F"
    letters += "P" if totals["P"] >= totals["J"] else "J"
    margins = {
        "IE": abs(totals["I"] - totals["E"]),
        "NS": abs(totals["N"] - totals["S"]),
        "TF": abs(totals["T"] - totals["F"]),
        "PJ": abs(totals["P"] - totals["J"]),
    }
    return {"letters": letters, "scores": totals, "margins": margins}


def score_mbti70(answers: List[AnswerMBTI]) -> Dict[str, Any]:
    if len(answers) != len(MBTI70_ITEMS):
        raise HTTPException(status_code=400, detail=f"Require {len(MBTI70_ITEMS)} answers for MBTI-70")
    ans_map = {a.item: a.choice.upper() for a in answers}
    # Validate choices
    for i in range(1, len(MBTI70_ITEMS) + 1):
        choice = ans_map.get(i)
        if choice not in ("A", "B"):
            raise HTTPException(status_code=400, detail=f"Item {i}: choice must be 'A' or 'B'")
    # Count selections per column
    col_counts = {c: {"A": 0, "B": 0} for c in range(1, 8)}
    for i, choice in ans_map.items():
        col = ((i - 1) % 7) + 1
        col_counts[col][choice] += 1
    totals = {k: 0 for k in ["E", "I", "S", "N", "T", "F", "J", "P"]}
    for col, (left, right) in COLUMN_TO_DIM.items():
        totals[left] += col_counts[col]["A"]
        totals[right] += col_counts[col]["B"]
    letters = ""
    letters += "I" if totals["I"] >= totals["E"] else "E"
    letters += "N" if totals["N"] >= totals["S"] else "S"
    letters += "T" if totals["T"] >= totals["F"] else "F"
    letters += "P" if totals["P"] >= totals["J"] else "J"
    margins = {
        "IE": abs(totals["I"] - totals["E"]),
        "NS": abs(totals["N"] - totals["S"]),
        "TF": abs(totals["T"] - totals["F"]),
        "PJ": abs(totals["P"] - totals["J"]),
    }
    return {"letters": letters, "scores": totals, "margins": margins}


# -----------------------------------------------------------------------------
# FastAPI app
# -----------------------------------------------------------------------------

app = FastAPI(title="URP MBTI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust as needed for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# -----------------------------------------------------------------------------
# Authentication endpoints
# -----------------------------------------------------------------------------

@app.post("/api/register", response_model=UserOut)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = get_user_by_email(db, user_in.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(user_in.password)
    user = User(email=user_in.email, hashed_password=hashed, full_name=user_in.full_name)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# -----------------------------------------------------------------------------
# User and result endpoints
# -----------------------------------------------------------------------------

@app.get("/api/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/api/me/results", response_model=List[ResultOut])
def get_my_results(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(TestResult).filter(TestResult.user_id == current_user.id).order_by(TestResult.created_at.desc()).all()


# -----------------------------------------------------------------------------
# Test endpoints
# -----------------------------------------------------------------------------

@app.get("/api/questions")
def get_questions(test: str):
    """Return list of question objects for the requested test.

    test: "psi32" or "mbti70" (case-insensitive)
    """
    t = test.lower()
    if t == "psi32":
        return [{"item": i, "a": PSI_ITEMS[i]["a"], "b": PSI_ITEMS[i]["b"]} for i in range(1, 33)]
    elif t == "mbti70":
        # If MBTI70_ITEMS does not have full 70 entries, raise
        if len(MBTI70_ITEMS) < 70:
            raise HTTPException(status_code=500, detail="MBTI70 question set incomplete")
        return [{"item": i, "a": MBTI70_ITEMS[i]["a"], "b": MBTI70_ITEMS[i]["b"]} for i in range(1, 71)]
    else:
        raise HTTPException(status_code=400, detail="Invalid test code")


@app.post("/api/score")
def score_test(test: str, save: bool = False, current_user: Optional[User] = Depends(get_current_user), db: Session = Depends(get_db), answers: List[Dict[str, Any]] = []):
    """Score a test. Provide answers list according to test type.

    For PSI‑32: answers = [{"item": i, "value": v}, ...] where v is 0–5.
    For MBTI‑70: answers = [{"item": i, "choice": "A"/"B"}, ...]

    If save=True and user is authenticated, result is persisted and returned with id; otherwise id is omitted.
    """
    t = test.lower()
    if t == "psi32":
        parsed = [AnswerPSI(**ans) for ans in answers]
        result = score_psi32(parsed)
        test_code = "PSI32"
    elif t == "mbti70":
        parsed = [AnswerMBTI(**ans) for ans in answers]
        result = score_mbti70(parsed)
        test_code = "MBTI70"
    else:
        raise HTTPException(status_code=400, detail="Invalid test code")

    # Persist result if requested and user authenticated
    if save:
        if current_user is None:
            raise HTTPException(status_code=401, detail="Authentication required to save result")
        tr = TestResult(
            user_id=current_user.id,
            test_code=test_code,
            type4=result["letters"],
            scores=result["scores"],
            margins=result["margins"],
        )
        db.add(tr)
        db.commit()
        db.refresh(tr)
        result_out = {
            "id": tr.id,
            "test_code": test_code,
            "type4": tr.type4,
            "scores": tr.scores,
            "margins": tr.margins,
            "created_at": tr.created_at,
        }
        return result_out
    else:
        return result


# -----------------------------------------------------------------------------
# Index route to serve spa fallback (optional)
# -----------------------------------------------------------------------------
@app.get("/{path:path}", include_in_schema=False)
def serve_spa(path: str, request: Request):
    """
    SPA fallback: for any unknown path, serve index.html so that the front-end router can handle it.
    The static index.html should load the appropriate page based on client-side router.
    """
    from fastapi.responses import FileResponse
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Not found"}

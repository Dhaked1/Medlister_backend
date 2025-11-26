from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.patients import router as patients_router
from app.auth import router as auth_router

app = FastAPI(title="Patient Management API")

allowed_origins = [
    "https://dhaked1.github.io",  # GitHub Pages origin
    "http://localhost:5173",         # Vite dev
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,          # keep True only with explicit origins
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(patients_router, prefix="/patients", tags=["Patients"])
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])

@app.get("/")
def root():
    return {"message": "Patient Management API is running"}
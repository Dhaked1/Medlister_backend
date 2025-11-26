from fastapi import APIRouter, HTTPException, Path, Query
from fastapi.responses import JSONResponse
from app.models import Patient, PatientUpdate
from app.firebase_client import patients_ref

router = APIRouter()

# -----------------------------
# Add new patient
# -----------------------------
@router.post("/")
def add_patient(patient: Patient):
    if patients_ref.child(patient.id).get() is not None:
        raise HTTPException(status_code=400, detail="Patient ID already exists")
    
    # Save patient including computed fields
    patients_ref.child(patient.id).set(patient.model_dump())
    
    return JSONResponse(
        content={
            "message": "Patient added successfully",
            "patient": patient.model_dump()
        },
        status_code=201
    )

# -----------------------------
# Get all patients
# -----------------------------
@router.get("/viewAll")
def get_all_patients():
    data = patients_ref.get()
    if not data:
        return {"patients": []}
    
    # Sort by most recently added (Firebase keys are IDs; optional: add timestamp)
    sorted_patients = sorted(
        data.values(),
        key=lambda x: x.get("id", ""),  
        reverse=True
    )
    return {"patients": sorted_patients}

# -----------------------------
# Get patient by ID
# -----------------------------
@router.get("/view/{patient_id}")
def get_patient(patient_id: str = Path(..., description="Enter the patient ID", example="P001")):
    patient = patients_ref.child(patient_id).get()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patient

# -----------------------------
# Sort patients by field
# -----------------------------
@router.get("/sort")
def sort_patients(
    sort_by: str = Query(..., description="Sort by 'height', 'weight', or 'age'"),
    order_by: str = Query("asc", description="Sort order: 'asc' or 'desc'")
):
    valid_fields = ['height', 'weight', 'age']
    if sort_by not in valid_fields:
        raise HTTPException(status_code=400, detail=f"Invalid field. Choose from {valid_fields}")
    if order_by not in ['asc', 'desc']:
        raise HTTPException(status_code=400, detail="Invalid order. Choose 'asc' or 'desc'")

    data = patients_ref.get()
    if not data:
        return {"patients": []}

    reverse = order_by == 'desc'
    sorted_data = sorted(data.values(), key=lambda x: x.get(sort_by, 0), reverse=reverse)
    return {"patients": sorted_data}

# -----------------------------
# Update patient
# -----------------------------
@router.put("/update/{patient_id}")
def update_patient(patient_id: str, patient_update: PatientUpdate):
    existing = patients_ref.child(patient_id).get()
    if not existing:
        raise HTTPException(status_code=404, detail="Patient not found")

    update_data = patient_update.model_dump(exclude_unset=True)
    updated_patient = {**existing, **update_data}
    updated_patient['id'] = patient_id  # Ensure ID stays the same

    # Validate using Patient model
    validated_patient = Patient(**updated_patient)
    patients_ref.child(patient_id).set(validated_patient.model_dump())
    
    return {
        "message": "Patient updated successfully",
        "patient": validated_patient.model_dump()
    }

# -----------------------------
# Delete patient
# -----------------------------
@router.delete("/delete/{patient_id}")
def delete_patient(patient_id: str):
    existing = patients_ref.child(patient_id).get()
    if not existing:
        raise HTTPException(status_code=404, detail="Patient not found")
    patients_ref.child(patient_id).delete()
    return {"message": "Patient deleted successfully"}

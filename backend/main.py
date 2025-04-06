from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from query import process_query

app = FastAPI()

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Change this for production to specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class QueryRequest(BaseModel):
    query: str

@app.get("/")
async def read_root():
    return {"message": "Welcome to the Natural Language to SQL Query Execution API"}

@app.post("/execute_query/")
async def execute_query(request: QueryRequest):
    try:
        response = process_query(request.query)
        if "error" in response:
            raise HTTPException(status_code=500, detail=response["error"])
        return response  # Returns {"sql_query": "...", "result": [...]}
    except HTTPException as http_err:
        raise http_err  # Keep HTTP errors as they are
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected Error: {str(e)}")

# FastAPI apps are typically run using: uvicorn main:app --reload

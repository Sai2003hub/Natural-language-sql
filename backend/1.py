import google.generativeai as genai
import os

# Set the API key
os.environ["GOOGLE_API_KEY"] = "AIzaSyDT61Cz6jplIKqoaxomm-25Cc3iVmhg63g"
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

def get_gemini_response(question, prompt):
    model = genai.GenerativeModel('models/gemini-1.5-pro')
    response = model.generate_content(contents=f"{prompt}\n{question}")
    return response

response = get_gemini_response("find the total salary of employees", "Convert the following natural language query to a SQL query:")
print("Response attributes:")
for attr in dir(response):
    if not attr.startswith("__"):
        print(f"{attr}: {getattr(response, attr)}")
        ["http://localhost:3000"]
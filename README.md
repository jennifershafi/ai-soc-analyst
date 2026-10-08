# AI SOC Analyst

This is a cybersecurity project based on Python to detect suspicious activity within a security log while using a local AI model helps investigating the alerts$

## What it does

The project reads security events from a JSON file and checks for suspicious patterns.

The JSON file used for this project is a simulated network log that i created in order to test this project.

The activities it does contains:
 
- Repeated failed login attempts
- Successful authentication after multiple failures
- File access or downloads following suspicious authentication

The detected alerts are displayed in a Streamlit dashboard.$

## Tools Used

- Python
- Streamlit
- Ollama (Qwen3 4B Instruct)
- JSON
- Git and GitHub

## How to Run

1. Install Python, Streamlit, and Ollama.
2. Download the local model: 
   `ollama pull qwen3:4b-instruct-2507-q4_K_M`
3. Start Ollama if it is not already running.
4. From the project directory, run:
   `python3 -m streamlit run dashboard.py`
5. Open the local dashboard and select Analyze Incident.

## Testing

The simulated security events involves five failed login attempts, a successful login with MFA combined with a file access or download activity after suspicious authentication process.

The engine generated four alerts: three high severity and one medium severity.

## Limitations

- The project currently uses a small simulated dataset rather than live security logs.
- Detection is based on simple rules and thresholds.
- The AI can sometimes make assumptions that are not fully supported by the evidence, so its findings need human review.

## Scalability

- This project can potentially be adopted into an environment with larger datasets, which would in turn make a SOC analysts job, much reliable and stronger.
- Doing this would require additional log sources, and processing events in batches.

##Thank You.

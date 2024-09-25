from mitmproxy import http
import os
from datetime import datetime
import subprocess

def request(flow: http.HTTPFlow) -> None:
    if flow.request.method == "POST" and "git-receive-pack" in flow.request.path:
        try:
            # Get current time for unique file name
            current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Extract the Host header and the request path to form the full repository URL
            host = flow.request.headers.get("Host")
            path = flow.request.path

            # Construct the full repository URL (assuming it's HTTPS)
            repo_url = f"https://{host}{path}"
            
            # Log the repository URL
            print(f"Repository URL: {repo_url}")
            
            # Define a local directory to clone the repository into
            clone_dir = f"/path/to/clone/repo_{current_time}"
            
            # Create the directory if it does not exist
            os.makedirs(clone_dir, exist_ok=True)
            
            # Clone the repository locally
            print(f"Cloning repository to {clone_dir}")
            subprocess.run(["git", "clone", repo_url, clone_dir], check=True)

            # Log success
            print(f"Successfully cloned repository: {repo_url} to {clone_dir}")
        
        except subprocess.CalledProcessError as e:
            # Log any errors during the clone process
            print(f"Error cloning repository: {e}")
        
        except Exception as e:
            # Catch all other exceptions
            print(f"Unexpected error: {str(e)}")


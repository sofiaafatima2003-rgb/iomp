import subprocess
import sys

def install_packages():
    packages = ["flask", "scikit-learn", "tensorflow", "pandas", "numpy", "joblib"]
    
    print(f" Using Python at: {sys.executable}")
    print(" STARTING INSTALLATION... (This may take 2-5 minutes)")
    
    for package in packages:
        print(f" Installing {package}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f" {package} installed!")
        except Exception as e:
            print(f" Failed to install {package}: {e}")

    print("\n COMPLETE! Now go to app.py and click Play.")

if __name__ == "__main__":
    install_packages()
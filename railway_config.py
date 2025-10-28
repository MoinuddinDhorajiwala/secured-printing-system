# Deployment Configuration
# This file contains deployment-specific settings

import os

# Railway provides DATABASE_URL automatically
# No additional configuration needed for Railway deployment

# Ensure we're using Railway's database
if not os.environ.get('DATABASE_URL'):
    raise ValueError("DATABASE_URL environment variable is required for Railway deployment")

print("Railway deployment configuration loaded successfully")
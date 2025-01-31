# LinkedIn Sales Navigator Scraper

A Streamlit application for scraping LinkedIn Sales Navigator data.

## Setup Instructions

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   ```
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Mac/Linux: `source venv/bin/activate`

4. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

5. Create a `.env` file with your configuration (see `.env.example`)

6. Run the application:
   ```bash
   streamlit run scraper_appv2.py
   ```

## Environment Variables

Required environment variables in `.env`:
- SECRET_KEY: Fernet encryption key
- SALT: Password hashing salt
- Other configuration values
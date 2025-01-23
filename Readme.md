## motivation

To understand the SSO process on Azure.

- The App is able to fetch tokens from the Azure when user enters thier cred on MS login.
- App has the ability to validate and decode token using proper keys using JWKS.(ref: https://robertoprevato.github.io/Validating-JWT-Bearer-tokens-from-Azure-AD-in-Python/)

## Azure Portal Configuration

Step 1: Create an App Registration

- Open the Azure Portal.

- Navigate to Azure Active Directory > App registrations.

- Select New registration and configure the following:

- Name: Enter a recognizable name for the app (e.g., FastAPIApp).

- Supported account types: Choose "Accounts in this organizational directory only" or another option as applicable.(Single Tenet)

- Redirect URI:

  - Select "Web".

  - Provide the URI http://<backend_domain>/auth/callback (replace <backend_domain> with the actual domain or localhost for testing).
  - for local testing : http://localhost:8000/auth/callback

Step 2: Note Down Key Details

- Application (client) ID: Found on the app's Overview page.

- Directory (tenant) ID: Also available on the app's Overview page.

- Client Secret:

  - Go to Certificates & secrets > New client secret.

  - Add a description and set an expiration period.

  - Copy and save the secret value (it will not be shown again).

Step 3: Configure API Permissions

- Go to API permissions.

- Select Add a permission > Microsoft Graph > Delegated permissions.

- Add these permissions:

  - openid

  - profile

  - email

  - User.Read

- Click Grant admin consent to apply these permissions across the organization.

Step 4: Verify Redirect URI

- Confirm that the Redirect URI http://<backend_domain>/auth/redirect matches the backend configuration.-

## CLAIMS - USER INFO IN ACCESS TOKEN

Ensure Claims Are Present in the Access Token

Azure AD access tokens can include claims such as name, email, and roles if configured correctly.
Steps to Include Claims in Access Token:

    Go to Azure Active Directory > App registrations > Your App.
    Navigate to Token Configuration:
        Click on Add optional claim.
        Choose Access token.
        Select claims like:
            email (User's email).
            given_name (User's first name).
            family_name (User's last name).
            roles (User's roles, if defined).
        Save changes.
    If required, grant admin consent for the changes:
        Go to API Permissions.
        Click Grant admin consent.

## Refresh

How to Fix or Debug

1. Verify Azure AD Configuration:

   - Check the token lifetime policies in Azure AD:
     - Navigate to Azure Active Directory > Conditional Access > Token Lifetime Policies.
     - Confirm if a policy explicitly limits the refresh token's lifetime.

2. Inspect Application Type:

   - Ensure your application supports the "offline_access" scope and the refresh token feature:
     - Go to Azure AD > App Registrations > Your App > API Permissions.
     - Ensure offline_access is granted and consented.

3. Test With an Enterprise Account:

   - If you are using a personal account, the behavior might differ.
   - Test with an enterprise Azure AD account to verify if the refresh_token_expires_in behaves as expected.

4. Use a Long-Lived Refresh Token:
   - Request longer-lived tokens using Continuous Access Evaluation (CAE) and policies:
     - Ensure your app supports Conditional Access policies that extend refresh token lifetimes.

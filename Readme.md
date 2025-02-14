## Project setup
   using Uv as python package manager.
   $ uv venv
   $ source .venv/bin/activate
   $ uv pip install -r requirement.text 

## Create a .env file to store the environment variables:

   CLIENT_ID=client_id
   CLIENT_SECRET=client_secert
   TENANT_ID=tenet_id
   REDIRECT_URI=callback_url

## motivation

To understand the SSO process on Azure.

- The App is able to fetch tokens from the Azure when user enters thier cred on MS login.
- App has the ability to validate and decode token using proper keys using JWKS.(ref: https://robertoprevato.github.io/Validating-JWT-Bearer-tokens-from-Azure-AD-in-Python/)

## Azure Portal Configuration for local development

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

---

# Azure Function App with SSO, Token Validation, and Role-Based Access

This document provides a step-by-step guide to implementing Single Sign-On (SSO), access token validation, and role-based access control for an Azure Function App in an enterprise Azure account.

---

## **1. Prepare the Azure Environment**

1. **Ensure Azure AD is available**: Verify that your organization uses Azure Active Directory (Azure AD) for identity management.
2. **Enterprise subscription**: Confirm access to an enterprise Azure account with necessary permissions for Azure AD and Azure resources.

---

## **2. Register the Application in Azure AD**

1. **Go to Azure AD in Azure Portal**:
   - Navigate to **Azure Active Directory** > **App Registrations**.
2. **Register your Function App**:
   - Click **New Registration**.
   - Provide a **Name** (e.g., `FunctionAppSSO`).
   - Specify the **Supported account types**:
     - Single tenant (only for your organization) or multi-tenant (for external users as well).
   - Set a **Redirect URI** for your Function App:
     - Example: `https://<your-function-app-name>.azurewebsites.net/.auth/login/aad/callback`.
3. **Save Key Details**:
   - Note the **Application (client) ID** and **Directory (tenant) ID** for later use.

---

## **3. Configure Authentication for the Function App**

1. **Enable App Service Authentication**:
   - Go to your Function App in the Azure Portal.
   - Navigate to **Authentication** > **Add Identity Provider**.
   - Choose **Microsoft** (Azure AD).
   - Select the Azure AD app registration you created.
   - Define an **Authentication Callback URL** (`/.auth/login/aad/callback`).
2. **Set Login Behavior**:
   - Choose **Log in with Azure AD only** to restrict access.

---

## **4. Create a Client Secret**

1. **Create a Client Secret**:
   - In your Azure AD **App Registration**, go to the **Certificates & Secrets** section.
   - Click **New Client Secret**:
     - Provide a description (e.g., `FunctionAppSecret`).
     - Set an expiration period (e.g., 6 months, 1 year, or custom).
   - Copy the **Value** immediately (you won’t be able to view it later).
2. **Use Client Secret**:
   - Save this secret securely in Azure Key Vault or your app's configuration settings.
   - For validation, combine it with the **Client ID** when making secure API calls.

---

## **5. Expose an API**

If your Function App acts as an API for other clients:

1. **Define API Scopes**:
   - Go to the **App Registration** for your Function App.
   - Navigate to **Expose an API** and click **Set** for the Application ID URI (if not already set):
     - Example: `api://<your-client-id>`.
   - Click **Add a Scope**:
     - Scope name: `access_as_user`.
     - Admin consent display name: `Access FunctionApp as User`.
     - Admin consent description: `Allows the application to access FunctionApp on behalf of the signed-in user`.
     - State: **Enabled**.
2. **Grant Permissions to Clients**:
   - If other applications need to call this API, grant them permission to this scope in their **App Registration** under **API Permissions**.

---

## **6. Update API Permissions**

1. **Grant API Permissions in Azure AD**:
   - In the **App Registration** section of Azure AD, go to **API Permissions**.
   - Click **Add a Permission** > **Microsoft Graph** > Choose permissions like:
     - **User.Read** (basic profile info).
     - **Directory.Read.All** (optional, for roles/groups).
2. **Admin Consent**:
   - Grant admin consent for the permissions.

---

## **7. Configure Issuer for Token Validation**

1. **Issuer URL**:
   - The issuer URL is specific to your tenant. It’s usually in the format:
     ```
     https://login.microsoftonline.com/{tenant-id}/v2.0
     ```
     Replace `{tenant-id}` with your Azure AD **Directory (tenant) ID**.
2. **Fetch Metadata**:
   - Azure AD publishes OpenID Connect (OIDC) metadata at:
     ```
     https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration
     ```
   - This metadata includes details like token signing keys (JWKS), supported algorithms, and endpoints.
3. **Validate Issuer in Function App**:
   - Ensure the **issuer** claim (`iss`) in the token matches the expected issuer URL.

---

## **8. Configure Role-Based Access**

1. **Define Roles in App Registration**:
   - Go to the **App Roles** section of your app registration.
   - Create roles like `Admin`, `User`, etc.:
     ```json
     "appRoles": [
       {
         "id": "unique-role-id",
         "allowedMemberTypes": ["User"],
         "description": "Admin role for Function App",
         "displayName": "Admin",
         "isEnabled": true,
         "value": "Admin"
       }
     ]
     ```
2. **Retrieve Roles in Access Token**:
   - Ensure roles are included in the **access token** by updating the app registration manifest.

---

## **9. Handle Access Token Validation**

1. **Validate Token**:
   - Decode the JWT token in your Function App backend.
   - Validate claims like `iss`, `aud`, and `exp`.
   - Example JWT payload:
     ```json
     {
       "iss": "https://login.microsoftonline.com/{tenant-id}/v2.0",
       "aud": "api://<your-client-id>",
       "roles": ["Admin", "User"],
       "exp": 1690000000
     }
     ```
2. **Enforce Roles**:
   - Use middleware to enforce role-based access.
     - Python (FastAPI): Use `Depends` to check roles.
     - .NET: Use `[Authorize(Roles = "Admin")]`.

---

## **10. Test and Debug**

1. Use tools like **Postman** or **curl** to test authentication and token validation.
2. Ensure the Azure AD token endpoint is configured for acquiring tokens.
3. Verify that users can log in, and roles are assigned correctly.

---

## **11. Enable Secure Communication**

1. **Configure HTTPS**:
   - Ensure HTTPS is enabled for your Function App.
2. **Secure Secrets**:
   - Store client secrets in Azure Key Vault.
3. **Diagnostics**:
   - Enable logging for authentication/authorization.
   - Use Application Insights for monitoring and debugging issues.

---

## **12. Deploy and Monitor**

1. Deploy your Function App via CI/CD pipelines.
2. Use Azure Monitor and Application Insights to track authentication and role access performance.

---

This guide ensures secure implementation of SSO, token validation, and role-based access for your Azure Function App.

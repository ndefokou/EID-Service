# German eID Service Backend

This repository contains the Node.js/TypeScript backend for the German eID Service, designed to handle eID authentication flows, user management, and API integrations.

## Project Structure

- `src/`: Contains all source code for the backend application.
  - `app.ts`: Main Express application setup.
  - `server.ts`: Entry point for starting the server.
  - `config/`: Configuration files for various aspects of the application (e.g., eID, database, server settings).
  - `middleware/`: Express middleware functions (e.g., authentication, error handling, validation).
  - `controllers/`: Request handlers for different API routes, containing the business logic.
  - `services/`: Encapsulates external service integrations and complex business logic.
    - `auth/`: Authentication related services (e.g., JWT, password hashing).
    - `eid/`: Logic for interacting with the German eID server (TR-03124).
    - `external/`: Services for other external APIs (e.g., SMS, email).
  - `models/`: Database models (e.g., Mongoose schemas for MongoDB).
  - `routes/`: Defines API endpoints and links them to controllers.
  - `utils/`: Reusable utility functions (e.g., helper functions, validation).
  - `types/`: Custom TypeScript type definitions.
- `certificates/`: Stores cryptographic certificates required for eID communication.
  - `rp/`: Relying Party (our service) certificates.
  - `trusted/`: Trusted certificates (e.g., eID server CA certificates).
  - `revoked_certs/`: Certificate Revocation Lists (CRLs).
- `tests/`: Contains unit and integration tests.
- `.env`, `.env.production`: Environment variables for different deployment stages.
- `package.json`: Project dependencies and scripts.
- `tsconfig.json`: TypeScript compiler configuration.
- `.gitignore`: Specifies intentionally untracked files.

## Getting Started

### Prerequisites

- Node.js (v18 or later recommended)
- npm or yarn
- TypeScript

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-org/eid-service.git
    cd eid-service/backend
    ```
2.  **Install dependencies:**
    ```bash
    npm install
    # or
    yarn install
    ```
3.  **Configure environment variables:**
    Create a `.env` file in the `backend/` directory based on the `.env.example` (or the provided `.env` in the current context).

    ```
    PORT=3001
    NODE_ENV=development
    JWT_SECRET=your_jwt_secret_key
    EID_RP_ID=your_relying_party_id
    EID_RP_NAME="Your Service Name"
    EID_CALLBACK_URL=http://localhost:3001/api/eid/callback
    EID_SERVER_URL=http://localhost:8080/eidas-eid-server
    CERT_PATH=./certificates
    TRUSTED_CERTS_PATH=${CERT_PATH}/trusted
    RP_CERT_PATH=${CERT_PATH}/rp
    CA_CERT_PATH=${CERT_PATH}/ca
    LOG_LEVEL=info
    ```

    **Important:** For production, ensure `JWT_SECRET` and other sensitive variables are managed securely (e.g., Kubernetes secrets, AWS Secrets Manager).

### Running the Application

1.  **Development Mode (with Hot Reload):**
    ```bash
    npm run dev
    # or
    yarn dev
    ```
    This will start the server using `nodemon` and `ts-node`, automatically recompiling and restarting on file changes.

2.  **Production Mode:**
    First, build the TypeScript code:
    ```bash
    npm run build
    # or
    yarn build
    ```
    Then, start the compiled JavaScript application:
    ```bash
    npm start
    # or
    yarn start
    ```

### Testing

Run unit and integration tests:
```bash
npm test
# or
yarn test
```

### Linting

Check for code style and errors:
```bash
npm run lint
# or
yarn lint
```

Fix linting errors automatically:
```bash
npm run lint:fix
# or
yarn lint:fix
```

## Certificates Management

The eID service relies heavily on cryptographic certificates. Ensure the `certificates/` directory is properly populated with:

-   **Relying Party (RP) Certificates:** Your service's own certificates for signing requests to the eID server.
-   **Trusted Certificates:** Certificates of the eID server's Certificate Authority (CA) and other trusted entities.
-   **Certificate Revocation Lists (CRLs):** For checking the revocation status of certificates.

**Note:** For development, you might use self-signed certificates or mock services. For production, obtain official certificates from a trusted CA.

## API Endpoints (Planned)

-   `/api/auth/register`: User registration
-   `/api/auth/login`: User login
-   `/api/auth/refresh-token`: Refresh JWT
-   `/api/eid/start-authentication`: Initiates eID authentication
-   `/api/eid/callback`: Callback endpoint for eID server (after user interaction)
-   `/api/eid/status/:transactionId`: Poll eID authentication status
-   `/api/eid/attributes/:transactionId`: Retrieve eID attributes
-   `/api/user/profile`: Get/Update user profile

## Contributing

Please adhere to the established coding standards and guidelines.

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Implement your changes and write tests.
4.  Ensure all tests pass and linting checks are green.
5.  Submit a pull request.

---
&copy; 2024 adorsys GmbH & Co. KG. All rights reserved.
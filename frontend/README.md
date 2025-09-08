# eID Service Frontend

This is the React TypeScript frontend for the German eID Service. It provides the user interface for initiating eID authentication, interacting with the eID client (Govenecus), obtaining user consent for attribute release, and displaying the results.

## Project Structure

The project follows a modular and scalable architecture:

*   **`public/`**: Static assets like `index.html` and `favicon.ico`.
*   **`src/assets/`**: Images, SVG icons, and global/component-specific stylesheets.
*   **`src/components/common/`**: Reusable, generic UI components (buttons, spinners, header, footer).
*   **`src/components/eid/`**: eID-specific UI components for the authentication flow (e.g., card reader status, PIN input, attribute consent).
*   **`src/config/`**: Configuration files for API endpoints and environment variables.
*   **`src/contexts/`**: React Contexts for global state management (authentication, eID flow).
*   **`src/hooks/`**: Custom React Hooks for reusable logic (e.g., `useEidClient`, `usePolling`).
*   **`src/pages/`**: Top-level page components for routing (Home, Login, Dashboard, EidCallback).
*   **`src/services/`**: Logic for API interactions with the backend (auth, eID, generic API client).
*   **`src/types/`**: Centralized TypeScript type definitions.
*   **`src/utils/`**: General utility functions (helpers, validation, logging).
*   **`src/App.tsx`**: Main application component, handles routing and overall layout.
*   **`src/index.tsx`**: Entry point for the React application.

## Getting Started

1.  **Install Dependencies:**
    ```bash
    cd frontend
    npm install
    # or yarn install
    ```
2.  **Environment Configuration:**
    Create a `.env` file in the `frontend/` directory (if not already present) and configure the `REACT_APP_API_BASE_URL` to point to your backend API.
    ```
    REACT_APP_API_BASE_URL=http://localhost:3001/api
    ```
3.  **Run in Development Mode:**
    ```bash
    npm start
    # or yarn start
    ```
    This will open the application in your browser (usually at `http://localhost:3000`).

4.  **Build for Production:**
    ```bash
    npm run build
    # or yarn build
    ```
    This creates a `build` directory with the optimized production-ready static assets.

## Integration with Govenecus eID Client

This frontend is designed to interact with an eID client like 'Govenecus' through a defined protocol, often involving deep links or custom URL schemes. The `useEidClient` hook and `eidService` will encapsulate the logic for initiating and managing this communication.

## Compliance

This frontend is built with compliance in mind, adhering to principles of:
*   **User Consent:** Explicit consent is gathered before attribute release.
*   **Data Minimization:** Only necessary data is handled.
*   **Security:** Secure communication practices are followed.

Refer to the overall `German_eID_Service_Architecture.md` for a complete overview of architectural considerations and compliance details.
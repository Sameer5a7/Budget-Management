// 🔹 Centralized function for API calls
async function fetchAPI(url, method = "GET", body = null) {
    try {
        const options = {
            method,
            headers: { "Content-Type": "application/json" },
            credentials: "include"  // ✅ Ensure cookies are sent
        };
        if (body) options.body = JSON.stringify(body);

        const response = await fetch(url, options);
        const data = await response.json();

        if (!response.ok) throw new Error(data.error || "An error occurred");
        return data;
    } catch (error) {
        console.error("API Error:", error);
        alert(error.message); // Consider using a more user-friendly notification system
        return null;
    }
}

// 🔹 Check Session and Redirect if Expired
async function checkSession() {
    try {
        const response = await fetch("http://localhost:4000/session", { credentials: "include" });

        console.log("🔍 Checking session...", response);

        if (!response.ok) {
            console.warn("Session expired, redirecting...");
            window.location.href = "login.html";
            return;
        }

        const data = await response.json();
        console.log("Session Active:", data);

        if (!data.user) {
            console.error("No user data found, redirecting...");
            window.location.href = "login.html";
            return;
        }

        const usernameDisplay = document.getElementById("username-display");
        if (usernameDisplay) {
            usernameDisplay.textContent = data.user.username || "Guest";
        }
    } catch (error) {
        console.error("Error fetching session:", error);
        window.location.href = "login.html";
    }
}


// 🔹 User Login
const loginForm = document.getElementById("login-form");
if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        const credentials = {
            email: document.getElementById("login-email").value,
            password: document.getElementById("login-password").value
        };

        const data = await fetchAPI("http://localhost:4000/login", "POST", credentials);
        if (data) {
            alert(data.message);
            console.log("User  data after login:", data.user); // Log user data for debugging
            
            // Update the UI with user data
            document.getElementById("username-display").innerText = data.user.username;
            document.getElementById("budget-amount").innerText = data.user.budget; // Ensure this is set
            document.getElementById("total-expenses").innerText = data.user.totalExpenses;
            document.getElementById("total-income").innerText = data.user.totalIncome;
            document.getElementById("remaining-budget").innerText = (data.user.budget - data.user.totalExpenses).toFixed(2); // Format to 2 decimal places
        
            // Redirect based on user role
            window.location.href = data.user.role === "admin" ? "admin-dashboard.html" : "index.html";
        }
    });
}
// 🔹 Logout
const logout = document.getElementById("logout"); // Get the logout button by its ID
if (logout) { // Check if the button exists
    logout.addEventListener("click", async () => { // Add a click event listener
        const data = await fetchAPI("http://localhost:4000/logout", "POST"); // Call the logout API
        if (data) { // If the API call is successful
            alert("Logged out successfully!"); // Show a success message
            window.location.href = "login.html"; // Redirect to the login page
        }
    });
}
// Run session check on page load
checkSession();
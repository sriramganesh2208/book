import "./navbar.css";
import { Link,  useNavigate } from "react-router-dom";
import { useContext } from "react";
import { AuthContext } from "../../context/AuthContext";
import { Button } from "@mui/material";

const Navbar = () => {
  const { user, dispatch } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogout = () => {
    dispatch({ type: "LOGOUT" });
    // Implement any additional logout logic (e.g., clearing local storage)
  };

  const handleRegister = () => {
    // Dispatch the action for starting the registration process
    dispatch({ type: "REGISTER_START" });
    // Redirect the user to the registration page
    navigate("/register");
  };

  return (
    <div className="navbar">
      <div className="navContainer">
        <Link to="/" style={{ color: "inherit", textDecoration: "none" }}>
          <span className="logo">Booking</span>
        </Link>
        <div className="navItems">
          {user ? (
            <>
              <span className="username">Welcome, {user.Username}</span>
              <button className="navButton" onClick={handleLogout}>Logout</button>
            </>
          ) : (
            <>
              <Button variant="contained" className="navButton" style={{color:"white"}} onClick={handleRegister}>Register</Button>
              <Link
                to="/login"
                style={{ color: "inherit", textDecoration: "none" }}
              >
                <Button variant="contained" className="navButton" style={{color:"white"}}>Login</Button> 
              </Link>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Navbar;

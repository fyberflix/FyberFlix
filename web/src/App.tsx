import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import Signup from "./pages/Signup";
import Login from "./pages/Login";
import Account from "./pages/Account";
import Profile from "./pages/Profile";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="signup" element={<Signup />} />
        <Route path="login" element={<Login />} />
        <Route path="account" element={<Account />} />
        {/* FyberFlix.zeaipc.in/{cable name} or /{FyberFlix number}: same destination */}
        <Route path=":ident" element={<Profile />} />
      </Route>
    </Routes>
  );
}

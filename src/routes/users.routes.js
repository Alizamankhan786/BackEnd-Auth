import express from "express";
import { loginUser , regitserUser } from "../controllers/users.controllers.js";


const router = express.Router();

// REGISTER USER

router.post("/register" , regitserUser);
router.post("/login" , loginUser);


export default router;
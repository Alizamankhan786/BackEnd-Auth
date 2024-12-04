import jwt from 'jsonwebtoken'
import bcrypt from "bcrypt";


// register user

const regitserUser = async (req , res) => {
    const {email , password} = req.body;

    if(!email) return res.status(400).json({
        message: "Email is required"
    });
    if(!password) return res.status(400).json({
        message: "Password is required"
    });

    const user = await user.findOne({
        email: email,
    });

    if(user) return res.status(401).json({
        message: "user already exist"
    });

    const createUser = await user.Create({
        email,
        password,
    });

    res.json({
        message: "User Registered Successfully" , data: createUser
    });

}
// login user

const loginUser = async (req , res) => {
    const {email , password} = req.body;

    if(!email) return res.status(400).json({
        message: "Email is required"
    });
    if(!password) return res.status(400).json({
        message: "Password is required"
    });

    const user = await user.findOne({
        email,
    });

    if(!user) return res.status(404).json({
        message: "No User Found"
    });

    const isPasswordValid = await bcrypt.compare(password , user.password);

    if(!isPasswordValid)
        return res.status(400).json({
      message: "Invalid Password",
    });
    
    // TOKEN GENERATE
    
    const accessToken = generateAcessToken(user);
    const refreshToken = generateRefreshToken(user);
    
    
    // COOKIES
    
    res.cookie("refreshToken" , refreshToken , {http: true , secure: false});
    
    res.json({
    message: "User Login SucessFully",
    accessToken,
    refreshToken,
    data: user,
});

};






// logout user
// refreshtoken

export {regitserUser , loginUser};
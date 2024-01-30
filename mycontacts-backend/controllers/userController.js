const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

// Register User
const registerUser = asyncHandler(async (req, res) => {
    const {username, email, password} = req.body;
    
    // Mandatory fields check 
    if(!username || !email || !password){
        res.status(400);
        throw new Error("All fields are mandatory!");
    }

    // Already registered user - email already taken
    const userAvailable = await User.findOne({email});
    if (userAvailable){
        res.status(400);
        throw new Error("Email already registered");
    }

    // Already registered user - username already taken
    const userNameAvailable = await User.findOne({username});
    if (userNameAvailable){
        res.status(400);
        throw new Error("Username already taken");
    }

    // Hash Password 
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed Password: ", hashedPassword);
    
    // Register user 
    const user = await User.create({
        username,
        email,
        password: hashedPassword
    });

    console.log(`User Created ${User}`);
    if(user){
        res.status(201).json({_id: user.id, email: user.email});
    }else{
        res.status(400);
        throw new Error("User data not valid");
    }

    res.json({message:"Register"});
});

// Login User
const loginUser = asyncHandler(async (req, res) => {
    const {email, password} = req.body;
    
    // Mandatory fields check 
    if(!email || !password){
        res.status(400);
        throw new Error("All fiels are mandatory!");
    }

    // check credentials - compare password and hashedPassword
    const user = await User.findOne({email});
    if(user && (await bcrypt.compare(password, user.password))){
        const accessToken = jwt.sign(
            {
                user: {
                    username: user.username,
                    email: user.email,
                    id: user.id 
                },
            },//payload to generate the token
            process.env.ACCESS_TOKEN_SECRET,
            {expiresIn: "30m"} //token expiry time
        );
        res.status(200).json({accessToken});
    }else{
        res.status(401);
        throw new Error("invalid creds!");
    }
    // res.json({message:"login"});
});

// Current User Info
const currentUser = asyncHandler(async (req, res) => {
    res.json(req.user);
});

module.exports = {registerUser, loginUser, currentUser};

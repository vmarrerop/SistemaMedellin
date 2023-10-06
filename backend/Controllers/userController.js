const userModel = require("../Models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

//==================> Create user <=======================
const register = async (req, res) => {
  try {
    const { username, email, phone, password } = req.body;

    if (!username || !email || !phone || !password) {
      return res.status(400).json("Por favor, completa todos los campos.");
    }

    // Verifica si el correo electrónico ya existe en la base de datos
    const existingUser = await userModel.findOne({ email });

    if (existingUser) {
      return res.status(400).json("El correo electrónico ya está registrado.");
    }

    // Hashea la contraseña antes de guardarla en la base de datos
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Crea el nuevo usuario en la base de datos
    const newUser = await userModel.create({
      username,
      email,
      phone,
      password: hashedPassword,
    });

    res.status(201).json({ message: "Registro exitoso.", user: newUser });
  } catch (error) {
    return res.status(500).json(error.message);
  }
};

//==================> Login user <=======================

// Cambia la función loginUser
const loginUser = async function (req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json("Por favor, ingresa correo electrónico y contraseña.");
    }

    // Verifica la existencia del usuario en la base de datos
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(401).json("Correo electrónico o contraseña incorrectos.");
    }

    // Compara las contraseñas
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json("Correo electrónico o contraseña incorrectos.");
    }

    // Aquí puedes retornar la respuesta de éxito, o hacer lo que necesites.
    res.status(200).json({ message: "Inicio de sesión exitoso." });
  } catch (error) {
    return res.status(500).json(error.message);
  }
};


//==================> Update user <=======================
const updateUser = async (req,res) => {
    try {
      let body = req.body
      
        const updatedUser = await userModel.updateOne({_id: req.params.id}, {$set : body})
        return res.status(200).json(updatedUser)
    } catch (error) {
        return res.status(500).json(error.message);
    }
}
//==================> Logout user <=======================
const logout = (req, res) => {
    res.clearCookie("access_token", {sameSite : "none", secure:true }).status(200).json( "User has been logged out. ")
};


//==================> Delete user <=======================
const deleteUser = async (req,res) => {
    try {
        
      const deletedUser = await userModel.deleteOne({_id : req.params.id})
      return res.status(200).json(deletedUser)
      
    } catch (error) {
        return res.status(500).json(error.message);
    }
}

module.exports = { register, loginUser, logout, deleteUser, updateUser };
const express = require("express");

const router = express.Router();

const {
    getContacts, 
    createContact, 
    getContact, 
    updateContact, 
    deleteContact
} = require("../controllers/contactController");
const validateToken = require("../middleware/validateTokenHandler");

// use validateToken for each route
router.use(validateToken);

router.route("/").get(getContacts).post(createContact);
router.route("/:id").get(getContact).put(updateContact).delete(deleteContact);

module.exports = router;
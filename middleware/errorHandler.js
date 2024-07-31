const {constants} = require("../constants")

const errorHandler = (err, req, res, next) => {
    const statusCode = res.statusCode ? res.statusCode : 500

    if(statusCode == constants.VALIDATION_ERROR){
        res.json({title: "Validation Failed", message: err.message, stackTrace: err.stack})
    }
    else if(statusCode == constants.NOT_FOUND){
        res.json({title: "Not Found", message: err.message, stackTrace: err.stack})
    }
    else if(statusCode == constants.UNAUTHORIZED){
        res.json({title: "Unauthorized", message: err.message, stackTrace: err.stack})
    }
    else if(statusCode == constants.FORBIDDEN){
        res.json({title: "Forbidden", message: err.message, stackTrace: err.stack})
    }
    else if(statusCode == constants.SERVER_ERROR){
        res.json({title: "Server Error", message: err.message, stackTrace: err.stack})
    }
    else{
        console.log("No Errors here, Happy Maintaining :)")
    }
}

module.exports = errorHandler


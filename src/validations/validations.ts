import Joi from "joi";

export const vendorValidationSchema = Joi.object({
    age: Joi.number().integer().min(0).required().messages({
        "any.required": "Age is required",
        "number.base": "Age must be a number",
    }),

    dob: Joi.date().required().messages({
        "any.required": "Date of birth is required",
    }),

    email: Joi.string().email().required().messages({
        "any.required": "Email is required",
        "string.email": "Invalid email format",
    }),

    firstName: Joi.string().min(1).required().messages({
        "any.required": "First name is required",
    }),

    password: Joi.string().pattern(
        new RegExp(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]).{8,}$"
        )).required().messages({
            "string.pattern.base": "Password must be at least 8 characters long, contain uppercase, lowercase, number, and special character",
        }),
    confirmPassword: Joi.string().pattern(
        new RegExp(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]).{8,}$"
        )).required().messages({
            "string.pattern.base": "Password must be at least 8 characters long, contain uppercase, lowercase, number, and special character",
        }),

    lastName: Joi.string().min(1).required().messages({
        "any.required": "Last name is required",
    }),

    address: Joi.string().min(1).required().messages({
        "any.required": "Address is required",
    }),

    city: Joi.string().min(1).required().messages({
        "any.required": "City is required",
    }),

    phone: Joi.string().pattern(/^\+?[0-9]{8,15}$/).required().messages({
        "any.required": "Phone number is required",
        "string.pattern.base": "Invalid phone number",
    }),

    pivaCode: Joi.string().required().messages({
        "string.base": "Invalid PIVA code",
    }),

    referralCode: Joi.string().optional().messages({
        "string.base": "Invalid referral code",
    }),

    shopName: Joi.string().required().messages({
        "any.required": "Shop name is required",
        "string.base": "Invalid shop name",
    }),

    zipCode: Joi.string().required().messages({
        "any.required": "Zip code is required",
        "string.base": "Invalid zip code",
    }),
});

export const vendorLoginSchema = Joi.object({
    email: Joi.string().email().required().messages({
        "any.required": "Email is required",
        "string.email": "Invalid email format",
    }),
    password: Joi.string().pattern(
        new RegExp(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]).{8,}$"
        )).required().messages({
            "string.pattern.base": "Password must be at least 8 characters long, contain uppercase, lowercase, number, and special character",
        }),
})

export const otpSchema = Joi.object({
    otp: Joi.string()
        .length(6)
        .pattern(/^[0-9]+$/)
        .required()
        .messages({
            "any.required": "OTP is required",
            "string.empty": "OTP cannot be empty",
            "string.length": "OTP must be exactly 6 digits",
            "string.pattern.base": "OTP must contain only numbers",
        }),
});

export const forgotPasswordSchema = Joi.object({
    email: Joi.string().email().required().messages({
        "any.required": "Email is required",
        "string.email": "Invalid email format",
    })
})

export const resetPasswordSchema = Joi.object({

    newPassword: Joi.string()
        .pattern(
            new RegExp(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]).{8,}$"
            )
        )
        .required()
        .messages({
            "any.required": "New password is required",
            "string.pattern.base":
                "New password must be at least 8 characters long, contain uppercase, lowercase, number, and special character",
        }),

    confirmPassword: Joi.any()
        .valid(Joi.ref("newPassword"))
        .required()
        .messages({
            "any.only": "Confirm password must match new password",
            "any.required": "Confirm password is required",
        }),
});


export const changePasswordSchema = Joi.object({

    oldPassword: Joi.string().required().messages({
        "any.required": "Old password is required",
        "string.empty": "Old password cannot be empty",
    }),

    newPassword: Joi.string()
        .pattern(
            new RegExp(
                "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=[\\]{};':\"\\\\|,.<>/?]).{8,}$"
            )
        )
        .required()
        .messages({
            "any.required": "New password is required",
            "string.pattern.base":
                "New password must be at least 8 characters long, contain uppercase, lowercase, number, and special character",
        }),

    confirmPassword: Joi.any()
        .valid(Joi.ref("newPassword"))
        .required()
        .messages({
            "any.only": "Confirm password must match new password",
            "any.required": "Confirm password is required",
        }),
});
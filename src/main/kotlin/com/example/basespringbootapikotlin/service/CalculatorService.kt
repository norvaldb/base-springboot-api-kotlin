package com.example.basespringbootapikotlin.service

import org.springframework.stereotype.Service

/**
 * Simple calculator service for demonstration purposes.
 * This service provides basic mathematical operations.
 */
@Service
class CalculatorService {

    /**
     * Adds two numbers.
     * @param a first number
     * @param b second number
     * @return sum of a and b
     */
    fun add(a: Int, b: Int): Int {
        return a + b
    }

    /**
     * Subtracts second number from first.
     * @param a first number
     * @param b second number
     * @return difference of a and b
     */
    fun subtract(a: Int, b: Int): Int {
        return a - b
    }

    /**
     * Multiplies two numbers.
     * @param a first number
     * @param b second number
     * @return product of a and b
     */
    fun multiply(a: Int, b: Int): Int {
        return a * b
    }

    /**
     * Divides first number by second.
     * @param a dividend
     * @param b divisor
     * @return quotient of a divided by b
     * @throws IllegalArgumentException if divisor is zero
     */
    fun divide(a: Int, b: Int): Double {
        if (b == 0) {
            throw IllegalArgumentException("Division by zero is not allowed")
        }
        return a.toDouble() / b.toDouble()
    }

    /**
     * Determines if a number is even.
     * @param number the number to check
     * @return true if even, false if odd
     */
    fun isEven(number: Int): Boolean {
        return number % 2 == 0
    }

    /**
     * Calculates factorial of a number.
     * @param n the number
     * @return factorial of n
     * @throws IllegalArgumentException if n is negative
     */
    fun factorial(n: Int): Long {
        if (n < 0) {
            throw IllegalArgumentException("Factorial is not defined for negative numbers")
        }
        return if (n <= 1) {
            1L
        } else {
            n * factorial(n - 1)
        }
    }

    /**
     * Finds maximum of two numbers.
     * @param a first number
     * @param b second number
     * @return maximum of a and b
     */
    fun max(a: Int, b: Int): Int {
        return if (a > b) a else b
    }
}

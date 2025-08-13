package com.example.basespringbootapikotlin.service

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class CalculatorServiceTest : DescribeSpec({

    val calculatorService = CalculatorService()

    describe("CalculatorService") {

        describe("add operation") {
            it("should add two positive numbers correctly") {
                calculatorService.add(5, 3) shouldBe 8
            }

            it("should add positive and negative numbers correctly") {
                calculatorService.add(10, -5) shouldBe 5
            }

            it("should add two negative numbers correctly") {
                calculatorService.add(-3, -7) shouldBe -10
            }

            it("should handle zero correctly") {
                calculatorService.add(0, 5) shouldBe 5
                calculatorService.add(5, 0) shouldBe 5
            }
        }

        describe("subtract operation") {
            it("should subtract two positive numbers correctly") {
                calculatorService.subtract(10, 3) shouldBe 7
            }

            it("should subtract negative from positive correctly") {
                calculatorService.subtract(10, -5) shouldBe 15
            }

            it("should handle zero correctly") {
                calculatorService.subtract(5, 0) shouldBe 5
                calculatorService.subtract(0, 5) shouldBe -5
            }
        }

        describe("multiply operation") {
            it("should multiply two positive numbers correctly") {
                calculatorService.multiply(4, 5) shouldBe 20
            }

            it("should multiply by zero correctly") {
                calculatorService.multiply(5, 0) shouldBe 0
                calculatorService.multiply(0, 5) shouldBe 0
            }

            it("should multiply negative numbers correctly") {
                calculatorService.multiply(-3, 4) shouldBe -12
                calculatorService.multiply(-3, -4) shouldBe 12
            }
        }

        describe("divide operation") {
            it("should divide two positive numbers correctly") {
                calculatorService.divide(10, 2) shouldBe 5.0
            }

            it("should divide with decimal result correctly") {
                calculatorService.divide(10, 3) shouldBe (10.0 / 3.0)
            }

            it("should throw exception when dividing by zero") {
                val exception = shouldThrow<IllegalArgumentException> {
                    calculatorService.divide(10, 0)
                }
                exception.message shouldBe "Division by zero is not allowed"
            }

            it("should handle negative numbers correctly") {
                calculatorService.divide(-10, 2) shouldBe -5.0
                calculatorService.divide(10, -2) shouldBe -5.0
            }
        }

        describe("isEven operation") {
            it("should return true for even numbers") {
                calculatorService.isEven(2) shouldBe true
                calculatorService.isEven(4) shouldBe true
                calculatorService.isEven(100) shouldBe true
                calculatorService.isEven(0) shouldBe true
            }

            it("should return false for odd numbers") {
                calculatorService.isEven(1) shouldBe false
                calculatorService.isEven(3) shouldBe false
                calculatorService.isEven(99) shouldBe false
            }

            it("should handle negative numbers correctly") {
                calculatorService.isEven(-2) shouldBe true
                calculatorService.isEven(-3) shouldBe false
            }
        }

        describe("factorial operation") {
            it("should calculate factorial of positive numbers correctly") {
                calculatorService.factorial(0) shouldBe 1L
                calculatorService.factorial(1) shouldBe 1L
                calculatorService.factorial(5) shouldBe 120L
                calculatorService.factorial(6) shouldBe 720L
            }

            it("should throw exception for negative numbers") {
                val exception = shouldThrow<IllegalArgumentException> {
                    calculatorService.factorial(-1)
                }
                exception.message shouldBe "Factorial is not defined for negative numbers"
            }
        }

        describe("max operation") {
            it("should return maximum of two positive numbers") {
                calculatorService.max(5, 3) shouldBe 5
                calculatorService.max(3, 5) shouldBe 5
            }

            it("should handle equal numbers") {
                calculatorService.max(5, 5) shouldBe 5
            }

            it("should handle negative numbers correctly") {
                calculatorService.max(-3, -5) shouldBe -3
                calculatorService.max(-3, 5) shouldBe 5
            }

            it("should handle zero correctly") {
                calculatorService.max(0, 5) shouldBe 5
                calculatorService.max(5, 0) shouldBe 5
                calculatorService.max(0, -5) shouldBe 0
            }
        }
    }
})

'use client'
import React from 'react'
import { Shield, Menu, X } from 'lucide-react'

function Navbar() {
  const [isMenuOpen, setIsMenuOpen] = React.useState(false)

  return (
    <nav className="bg-gradient-to-r from-blue-600 to-blue-800 shadow-lg">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Title */}
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-white" />
            <h1 className="text-white text-xl sm:text-2xl font-bold">
              Phishing Website Detection
            </h1>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-6">
            <a href="#home" className="text-white hover:text-blue-200 transition duration-200 font-medium">
              Home
            </a>
            <a href="#scan" className="text-white hover:text-blue-200 transition duration-200 font-medium">
              Scan URL
            </a>
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsMenuOpen(!isMenuOpen)}
              className="text-white hover:text-blue-200 focus:outline-none"
            >
              {isMenuOpen ? (
                <X className="h-6 w-6" />
              ) : (
                <Menu className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      {isMenuOpen && (
        <div className="md:hidden bg-blue-700">
          <div className="px-4 pt-2 pb-4 space-y-2">
            <a
              href="#home"
              className="block text-white hover:text-blue-200 py-2 transition duration-200 font-medium"
            >
              Home
            </a>
            <a
              href="#scan"
              className="block text-white hover:text-blue-200 py-2 transition duration-200 font-medium"
            >
              Scan URL
            </a>
            <a
              href="#about"
              className="block text-white hover:text-blue-200 py-2 transition duration-200 font-medium"
            >
              About
            </a>
            <a
              href="#contact"
              className="block text-white hover:text-blue-200 py-2 transition duration-200 font-medium"
            >
              Contact
            </a>
          </div>
        </div>
      )}
    </nav>
  )
}

export default Navbar
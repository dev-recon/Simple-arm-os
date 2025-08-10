/* Implementation simple de la division pour ARM */
unsigned int __aeabi_uidiv(unsigned int numerator, unsigned int denominator)
{
    unsigned int quotient = 0;
    
    if (denominator == 0) return 0;
    
    while (numerator >= denominator) {
        numerator -= denominator;
        quotient++;
    }
    
    return quotient;
}

unsigned int __aeabi_uidivmod(unsigned int numerator, unsigned int denominator)
{
    unsigned int quotient = __aeabi_uidiv(numerator, denominator);
    return numerator - (quotient * denominator);  /* reste */
}
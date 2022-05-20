/// Classes of the domain name system. Only the internet (IN) class
/// is supported in the project since other ones are unused/obsolete.
#[derive(Debug, Clone, Copy)]
pub enum Class {
    IN,
    CS,
    CH,
    HS,
    WC,
}

impl Class {
    /// Try to generate a [`Class`] from its raw number representation.
    pub fn from_num(n: u16) -> Result<Self, u16> {
        match n {
            1 => Ok(Class::IN),
            2 => Ok(Class::CS),
            3 => Ok(Class::CH),
            4 => Ok(Class::HS),
            255 => Ok(Class::WC),
            n => Err(n),
        }
    }

    /// Convert a [`Class`] to its raw number representation.
    pub fn to_num(&self) -> u16 {
        match self {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
            Class::WC => 255,
        }
    }

    /// Try to generate a [`Class`] from its raw string representation.
    pub fn from_string(s: &str) -> Result<Self, &str> {
        match s {
            "IN" => Ok(Class::IN),
            "CS" => Ok(Class::CS),
            "CH" => Ok(Class::CH),
            "HS" => Ok(Class::HS),
            "*" => Ok(Class::WC),
            _ => Err(s),
        }
    }

    /// Determine if a [`Class`] is supported in the system.
    pub fn is_supported(&self) -> bool {
        match self {
            Class::IN => true,
            _ => false,
        }
    }
}

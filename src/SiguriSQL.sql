create database siguri;
use siguri;
create TABLE userat(
	ID int AUTO_INCREMENT PRIMARY KEY,
    Emri text not null,
    Salt varchar(40) not null,
    Password text not null,
    Token text null
);

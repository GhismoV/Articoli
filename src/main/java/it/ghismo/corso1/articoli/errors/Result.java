package it.ghismo.corso1.articoli.errors;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.persistence.Inheritance;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@Inheritance
public @interface Result {
	String code();
	String msg() default "Generic Error";
	
}

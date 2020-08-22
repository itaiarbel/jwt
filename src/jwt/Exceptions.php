<?php
namespace Itaiarbel\Jwt\Exceptions;

/**
 * @author Itai Arbel <itai@arbelis.com> (c) 2020 Arbel Internet Solutions
 * @since 18-AUG-2020
 * @license MIT
 * @version Release: 1.0
 * @link https://github.com/itaiarbel/jwt
 */
class Exceptions extends \UnexpectedValueException
{
}

class Exception_AlgorithmNotFound extends Exceptions
{
}

class Exception_InvalidInput extends Exceptions
{
}

class Exception_AlgorithmNone extends Exceptions
{
}

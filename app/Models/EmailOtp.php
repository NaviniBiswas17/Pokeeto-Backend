<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
class EmailOtp extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'email_otps';
    protected $fillable = [
        'email',
        'otp',
        'purpose',
        'status',
        'expires_at',
        'used_at',
    ];

   
}
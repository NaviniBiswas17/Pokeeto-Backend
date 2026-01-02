<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
class UserDetail extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'user_details';
    protected $fillable = [
        'user_id',
        'name',
        'email',
        'phone',
        'dob',
        'status',
    ];

   
}
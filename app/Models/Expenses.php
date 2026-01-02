<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
class Expenses extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'expenses';
    protected $fillable = [
        'amount',
        'account_type',
        'category',
        'date',
        'comments',
        
    ];

   
}
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class KidDetail extends Authenticatable
{
    protected $table = 'kid_details';
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasApiTokens,HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'parent_id',
        'unique_Id',
         'name',
         'relation',
         'date_of_birth',
         'email',
         'email_verified_at',
         'password',
         'remember_token',
         'status'
    ];
}

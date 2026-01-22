<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class KidAccount extends Authenticatable
{
    protected $table = 'kid_accounts';
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasApiTokens,HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'account_name',
        'parent_id',
        'kid_id',
        'default_currency',
        'balance',
        'is_primary',
        'last_login_at',
        'metadata',
        'status'
    ];
}

<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
use App\Models\Account;
use App\Models\KidDetail;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'id',
        'name',
        'email',
        'password',
        'email_verified_at',
        'email',
        'status',
    ];

     // 🔹 User → Accounts
    public function accounts()
    {
        return $this->hasMany(Account::class, 'user_id');
    }

    // 🔹 User → Kids
    public function kids()
    {
        return $this->hasMany(KidDetail::class, 'parent_id');
    }

    public function friend_invites()
    {
        return $this->hasMany(FriendInvite::class, 'inviter_user_id');
    }

}

<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;
class ReminderPayment extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    protected $table = 'reminder_payments';
    protected $fillable = [
        'transaction_id',
        'reminder_date',
        'reminder_time',
        'recurrence',
        'notify_before_minutes',
        'status'
    ];


}

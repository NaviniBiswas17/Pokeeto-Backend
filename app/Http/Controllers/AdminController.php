<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Admin;
use App\Models\User;
use App\Models\EmailTemplate;
use App\Models\EmailOtp;
use App\Mail\MailTemp;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\MailLog;
use Illuminate\Support\Facades\Mail;
use App\Http\Controllers\Exception;
use Illuminate\Support\Str;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;

class AdminController extends Controller
{
    public function sendOtp(Request $request)
    {
        try {
            if(isset($request->email)){
                $request->validate([
                    'email' => 'required|email'
                ]);
                $admin = Admin::where([
                    'email' => $request->email,
                    'status' => 1
                ])->first();

                if(!$admin){
                    return response()->json([
                        'status'=>false,
                        'message'=>'Admin not found'
                    ]);
                }

                $otp = '123456'; // Generate OTP here
                $mailTemp = EmailTemplate::where('slug', 'sendLoginOtp')->first();
                $html = Blade::render($mailTemp->body, [
                    'otp' => $otp,
                    'validity_minutes' => env('OTP_VALIDITY_MINUTES', 10)
                ]);
                Mail::to($request->email)->send(new MailTemp($html, $mailTemp->subject));
                EmailOtp::where('email', $request->email)->where('purpose', 'admin_login')->update(['status' => '0']);
                EmailOtp::create([
                    "email" => $request->email,
                    "otp" => $otp,
                    "purpose" => 'admin_login',
                    "expires_at" => now()->addMinutes((int) env('OTP_VALIDITY_MINUTES', 10)),
                ]);
                MailLog::create([
                    'to_email' => $request->email,
                    'subject' => $mailTemp->subject,
                    'body' => $html,
                    'sent_at' => now(),
                ]);

                $token = $admin->createToken('api-token')->plainTextToken;

                Admin::where('id', $admin->id)->update(['email_verified_at' => now(), 'remember_token' => $token]);

                return response()->json([
                    'status' => true,
                    'message' => 'Otp Sent successfully',
                    'access_token' => $token,

                ]);

            }else{
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }

        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function adminLogin(Request $request)
    {
        try {
            if(isset($request->email) && isset($request->otp)){
                $request->validate([
                    'email'=>'required|email',
                    'otp'=>'required'
                ]);
                $admin = Admin::where([
                    'email'=>$request->email,
                    'status'=>1
                ])->first();

                if(!$admin){
                    return response()->json([
                        'status'=>false,
                        'message'=>'Invalid email'
                    ]);
                }

                $otpRecord = EmailOtp::where('email',$request->email)
                    ->where('otp',$request->otp)
                    ->where('purpose','admin_login')
                    ->where('expires_at','>',now())
                    ->where('status', '=', '1')
                    ->latest()
                    ->first();

                if(!$otpRecord){
                    return response()->json([
                        'status'=>false,
                        'message'=>'Invalid or Expired OTP'
                    ]);
                }
                $otpRecord->update(['used_at' => now(), 'status' => '0']);
                $token = $admin->createToken('api-token')->plainTextToken;

                $admin->update([
                    'remember_token'=>$token
                ]);

                return response()->json([
                    "status"=>true,
                    "access_token"=>$token,
                    'message'=>'Login successful'
                ]);
            } else{
                return response()->json([
                    'status'=>false,
                    'message'=>'Empty Parameters'
                ],400);
            }


        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }

    }

    public function verifySession(Request $request)
    {
        try {
            if (isset($request->token)) {
                $request->validate([
                    'token' => 'required',
                ]);
                $admin = Admin::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$admin) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                return response()->json([
                    'status' => true,
                    'message' => 'Session is valid',
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getAdminDetails(Request $request)
    {
        try {
            if (isset($request->token)) {
                $request->validate([
                    'token' => 'required',
                ]);
                $admin = Admin::where(['remember_token' => $request->token, 'status' => 1])->first();
                if (!$admin) {
                    return response()->json(['status' => false, 'message' => 'Invalid Credentials'], 500);
                }
                return response()->json([
                    'status' => true,
                    'message' => 'Admin details fetched successfully',
                    'data' => $admin
                ]);

            } else {
                return response()->json(['status' => false, 'message' => 'Empty Parameters'], 400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }

    public function getUsersList(Request $request){
        try{
            if(isset($request->token)){
                $request->validate([
                    'token'=>'required',
                ]);
                $admin = Admin::where(['remember_token'=>$request->token,'status'=>1])->first();
                if(!$admin){
                    return response()->json(['status'=>false,'message'=>'Invalid Credentials'],500);
                }
                if($admin->role != 'super_admin'){
                    return response()->json(['status'=>false,'message'=>'Access denied. Only SuperAdmin allowed.'],403);
                }
                $users = User::select('id', 'name', 'email', 'status', 'created_at')->where('status', 1)->get();
                return response()->json([
                    'status'=>true,
                    'message'=>'Users list fetched successfully',
                    'data'=>[
                        'users' => $users,
                        'total_users' => count($users)
                    ]
                ]);

            } else{
                return response()->json(['status'=>false,'message'=>'Empty Parameters'],400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }


    public function getUserDetails(Request $request)
    {
        try{
            if(isset($request->token) && isset($request->user_id)){
                $request->validate([
                    'token'=>'required',
                    'user_id'=>'required|exists:users,id'
                ]);
                $admin = Admin::where(['remember_token'=>$request->token,'status'=>1])->first();
                if(!$admin){
                    return response()->json(['status'=>false,'message'=>'Invalid Credentials'],500);
                }
                if($admin->role != 'super_admin'){
                    return response()->json(['status'=>false,'message'=>'Access denied. Only SuperAdmin allowed.'],403);
                }
                // $user = User::select('id', 'name', 'email', 'status')->where('id', $request->user_id)->first();

                $user = User::select('id','name','email','status')
                    ->withCount(['accounts','kids'])
                    ->with(['kids' => function($query){
                        $query->select('id','parent_id','name','unique_id','relation','date_of_birth','profile_image');
                    }, 'friend_invites' => function ($query){
                        $query->select('inviter_user_id','invitee_email','processStatus','status');
                    }])
                    ->where('id',$request->user_id)
                    ->first();
                return response()->json([
                    'status'=>true,
                    'message'=>'User details fetched successfully',
                    'data'=>$user
                ]);

            } else{
                return response()->json(['status'=>false,'message'=>'Empty Parameters'],400);
            }
        } catch (\Exception $e) {
            return response()->json(['status' => false, 'message' => $e->getMessage()], 500);
        }
    }
}

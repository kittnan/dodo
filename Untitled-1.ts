import { Injectable } from "@angular/core";
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse,
  HTTP_INTERCEPTORS,
  HttpClient,
  HttpHeaders,
} from "@angular/common/http";
import { Observable, throwError, BehaviorSubject, lastValueFrom } from "rxjs";
import { catchError, filter, take, switchMap, finalize } from "rxjs/operators";
import { AuthService2 } from "./authService2.service";
 
@Injectable()
export class TokenInterceptor implements HttpInterceptor {
  private isRefreshing = false;
 
 
  constructor(public authService: AuthService2,
    private http: HttpClient) { }
 
  refreshBoo = false
 
  refreshToken(): Observable<any> {
    const refreshToken = localStorage.getItem('refresh_token');
 
    const headers = new HttpHeaders({
      'Authorization1': 'Bearer ' + refreshToken
    });
 
    return this.http.post('http://localhost:3000/auth/refresh', {}, { headers })
  }
 
  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    let token: any = localStorage.getItem('access_token')
    request = this.addToken(request, token)
    console.log(request);
 
    return next.handle(request).pipe(
 
      catchError((error: HttpErrorResponse) => {
        console.log(error);
 
        if (error.status === 401 || error.status === 403) {
          if (!this.refreshBoo) {
            console.log('refreshBoo', this.refreshBoo);
            this.refreshBoo = true
            return this.refreshToken().pipe(
              switchMap((tokens: any) => {
                console.log('tokens', tokens);
                this.refreshBoo = false
                localStorage.setItem('access_token', tokens.access_token)
                localStorage.setItem('refresh_token', tokens.refresh_token)
                request = this.addToken(request, tokens.access_token)
                return next.handle(request)
              })
            )
          }
        }
        return throwError(error);
      })
    );
  }
 
  private addToken(request: HttpRequest<any>, token: string) {
    return request.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`,
      },
    });
  }
}
 
 
export const tokenInterceptor = {
  provide: HTTP_INTERCEPTORS,
  useClass: TokenInterceptor,
  multi: true
};
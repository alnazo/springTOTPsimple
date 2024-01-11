package com.adllo.springTOTPsimple.service;

import com.adllo.TOTP;
import com.adllo.springTOTPsimple.dto.UserDTO;
import com.adllo.springTOTPsimple.enums.Role;
import com.adllo.springTOTPsimple.model.User;
import com.adllo.springTOTPsimple.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    private User user;
    private UserDTO userDTO;

    @BeforeEach
    public void setup() {
        user = new User(
                1L,
                "a@a.es",
                new BCryptPasswordEncoder().encode("pass"),
                TOTP.generateBase32Secret(),
                Set.of(Role.USER)
        );

        userDTO = new UserDTO(
                "a@a.es",
                "pass"
        );
    }

    @Test
    public void givenUserObject_whenCreateUser_thenReturnUserObject() {
        when(userRepository.save(any(User.class)))
                .then(new Answer<User>() {
                    long sequence = 1;

                    @Override
                    public User answer(InvocationOnMock invocation) throws Throwable {
                        User user = (User) invocation.getArgument(0);
                        user.setId(sequence++);
                        return user;
                    }
                });

        User us = userService.createUser(userDTO);

        assertThat(us).isNotNull();
    }

    @Test
    public void givenExistingEmail_whenCreateUser_thenReturnNull() {
        when(userService.findByEmail(userDTO.getEmail())).thenReturn(user);

        User saveUser = userService.createUser(userDTO);

        verify(userRepository, never()).save(saveUser);
    }

    @Test
    public void givenUserObject_whenFindByEmail_thenReturnUserObject() {
        when(userRepository.findUserByEmail(user.getEmail())).thenReturn(user);

        User getUser = userService.findByEmail(user.getEmail());

        assertThat(getUser).isNotNull();
    }

    @Test
    public void givenUserObject_whenFindByEmail_thenReturnNull() {
        when(userRepository.findUserByEmail(user.getEmail())).thenReturn(null);

        User getUser = userService.findByEmail(user.getEmail());

        assertThat(getUser).isNull();
    }

    @Test
    public void giveNothing_whenAddAuthority_thenUpdate() {
        userService.addAuthority(user, Role.MFA_ACTIVE);

        assertTrue(user.getAuthority().contains(Role.MFA_ACTIVE));
    }

}
